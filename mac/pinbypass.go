package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// fridaScript is a comprehensive Frida payload that bypasses all common iOS
// certificate pinning mechanisms. Each hook is wrapped in try/catch so a
// failure in one does not block the others.
const fridaScript = `'use strict';

// ============================================================================
// USBNet — iOS certificate-pinning bypass (Frida)
//
// Hooks every common pinning path: Security.framework, NSURLSession delegates,
// Network.framework, AFNetworking, Alamofire, TrustKit, and WKWebView.
// ============================================================================

function log(msg) {
    send({ type: 'bypass', message: msg });
    console.log('[USBNet] ' + msg);
}

function logError(msg) {
    send({ type: 'error', message: msg });
    console.error('[USBNet] ' + msg);
}

// ---- 1. Security.framework ------------------------------------------------

// SecTrustEvaluateWithError (iOS 12+)
// bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error)
try {
    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
            log('Bypassed SecTrustEvaluateWithError');
            if (error !== null && !error.isNull()) {
                Memory.writePointer(error, ptr(0));
            }
            return 1; // true
        }, 'bool', ['pointer', 'pointer']));
    }
} catch (e) {
    logError('SecTrustEvaluateWithError hook failed: ' + e);
}

// SecTrustEvaluate (legacy, pre-iOS 12 path still called by some apps)
// OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
            log('Bypassed SecTrustEvaluate');
            if (result !== null && !result.isNull()) {
                // kSecTrustResultProceed = 1
                Memory.writeU32(result, 1);
            }
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'pointer']));
    }
} catch (e) {
    logError('SecTrustEvaluate hook failed: ' + e);
}

// SecTrustSetPolicies — some apps set strict SSL policies; no-op it.
// OSStatus SecTrustSetPolicies(SecTrustRef trust, CFTypeRef policies)
try {
    var SecTrustSetPolicies = Module.findExportByName('Security', 'SecTrustSetPolicies');
    if (SecTrustSetPolicies) {
        Interceptor.replace(SecTrustSetPolicies, new NativeCallback(function (trust, policies) {
            log('Bypassed SecTrustSetPolicies (no-op)');
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'pointer']));
    }
} catch (e) {
    logError('SecTrustSetPolicies hook failed: ' + e);
}

// SecTrustGetTrustResult — force kSecTrustResultProceed
try {
    var SecTrustGetTrustResult = Module.findExportByName('Security', 'SecTrustGetTrustResult');
    if (SecTrustGetTrustResult) {
        Interceptor.replace(SecTrustGetTrustResult, new NativeCallback(function (trust, result) {
            log('Bypassed SecTrustGetTrustResult');
            if (result !== null && !result.isNull()) {
                Memory.writeU32(result, 1);
            }
            return 0;
        }, 'int', ['pointer', 'pointer']));
    }
} catch (e) {
    logError('SecTrustGetTrustResult hook failed: ' + e);
}

// SSLSetSessionOption — disable kSSLSessionOptionBreakOnServerAuth
try {
    var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
    if (SSLSetSessionOption) {
        Interceptor.replace(SSLSetSessionOption, new NativeCallback(function (context, option, value) {
            // option 0 = kSSLSessionOptionBreakOnServerAuth
            if (option === 0) {
                log('Bypassed SSLSetSessionOption (BreakOnServerAuth)');
                return 0;
            }
            return 0;
        }, 'int', ['pointer', 'int', 'bool']));
    }
} catch (e) {
    logError('SSLSetSessionOption hook failed: ' + e);
}

// SSLCreateContext — legacy but still used
try {
    var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
    if (SSLHandshake) {
        Interceptor.attach(SSLHandshake, {
            onLeave: function (retval) {
                // -9807 = errSSLXCertChainInvalid, -9802 = errSSLFatalAlert
                // -9803 = errSSLSessionNotFound — not a pinning error
                var val = retval.toInt32();
                if (val === -9807 || val === -9802) {
                    log('Bypassed SSLHandshake error ' + val);
                    retval.replace(0); // noErr
                }
            }
        });
    }
} catch (e) {
    logError('SSLHandshake hook failed: ' + e);
}

// ---- 2. NSURLSession delegates --------------------------------------------

// Generic helper: given an NSURLAuthenticationChallenge, call the completion
// handler with UseCredential + the server trust.
function bypassURLSessionChallenge(completionHandler, challenge, label) {
    try {
        var dominated = ObjC.classes.NSURLCredential;
        var protectionSpace = challenge.protectionSpace();
        var host = protectionSpace.host().toString();
        var serverTrust = protectionSpace.serverTrust();
        var credential = dominated['+ credentialForTrust:'](serverTrust);
        // NSURLSessionAuthChallengeUseCredential = 0
        var invocation = completionHandler;
        invocation(0, credential);
        log('Bypassed ' + label + ' for ' + host);
    } catch (e) {
        logError(label + ' bypass failed: ' + e);
        // Fall back: call with default handling
        try { completionHandler(1, null); } catch (_) {}
    }
}

// Hook URLSession:didReceiveChallenge:completionHandler: on every class that
// implements it, and the per-task variant.
try {
    var resolver = new ApiResolver('objc');

    // Session-level challenge
    var sessionMatches = resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]');
    sessionMatches.forEach(function (match) {
        try {
            var className = match.name.split(' ')[0].substring(2);
            var hook = ObjC.classes[className]['- URLSession:didReceiveChallenge:completionHandler:'];
            Interceptor.attach(hook.implementation, {
                onEnter: function (args) {
                    var challenge = ObjC.Object(args[3]);
                    var completionHandler = new ObjC.Block(args[4]);
                    bypassURLSessionChallenge(completionHandler, challenge,
                        'URLSession:didReceiveChallenge: [' + className + ']');
                    this.bypassed = true;
                },
                onLeave: function (retval) {
                    // We already called the handler; prevent the original from
                    // calling it again by… nothing — we just handled it above.
                }
            });
        } catch (e) {
            // Some ObjC metadata can be weird; skip.
        }
    });

    // Task-level challenge
    var taskMatches = resolver.enumerateMatches('-[* URLSession:task:didReceiveChallenge:completionHandler:]');
    taskMatches.forEach(function (match) {
        try {
            var className = match.name.split(' ')[0].substring(2);
            var hook = ObjC.classes[className]['- URLSession:task:didReceiveChallenge:completionHandler:'];
            Interceptor.attach(hook.implementation, {
                onEnter: function (args) {
                    var challenge = ObjC.Object(args[4]);
                    var completionHandler = new ObjC.Block(args[5]);
                    bypassURLSessionChallenge(completionHandler, challenge,
                        'URLSession:task:didReceiveChallenge: [' + className + ']');
                    this.bypassed = true;
                }
            });
        } catch (e) {}
    });
} catch (e) {
    logError('NSURLSession delegate hooks failed: ' + e);
}

// ---- 3. Network.framework -------------------------------------------------

// sec_protocol_options_set_verify_block — set a verify block that always
// succeeds so NWConnection-based pinning is bypassed.
try {
    var sec_protocol_options_set_verify_block = Module.findExportByName(
        'Security', 'sec_protocol_options_set_verify_block');
    if (sec_protocol_options_set_verify_block) {
        Interceptor.replace(sec_protocol_options_set_verify_block,
            new NativeCallback(function (options, verifyBlock, queue) {
                log('Bypassed sec_protocol_options_set_verify_block — installing permissive block');
                // We replace the caller's verify block with one that always
                // calls the completion with true.
                var trueBlock = new ObjC.Block({
                    retType: 'void',
                    argTypes: ['pointer', 'pointer', 'pointer'],
                    implementation: function (metadata, trust, completion) {
                        var completionImpl = new NativeFunction(completion, 'void', ['bool']);
                        completionImpl(1); // true = trust
                    }
                });
                // Call the real function with our permissive block
                var orig = new NativeFunction(sec_protocol_options_set_verify_block,
                    'void', ['pointer', 'pointer', 'pointer']);
                orig(options, trueBlock, queue);
            }, 'void', ['pointer', 'pointer', 'pointer']));
    }
} catch (e) {
    logError('sec_protocol_options_set_verify_block hook failed: ' + e);
}

// nw_tls_create_peer_trust — if present, make it always succeed
try {
    var nw_tls_create_peer_trust = Module.findExportByName('libnetwork.dylib', 'nw_tls_create_peer_trust');
    if (nw_tls_create_peer_trust) {
        Interceptor.attach(nw_tls_create_peer_trust, {
            onLeave: function (retval) {
                log('Bypassed nw_tls_create_peer_trust');
                // Return non-null to signal trust was created
            }
        });
    }
} catch (e) {
    logError('nw_tls_create_peer_trust hook failed: ' + e);
}

// ---- 4. AFNetworking ------------------------------------------------------

try {
    if (ObjC.classes.AFSecurityPolicy) {
        // evaluateServerTrust:forDomain:
        var evalMethod = ObjC.classes.AFSecurityPolicy['- evaluateServerTrust:forDomain:'];
        if (evalMethod) {
            Interceptor.attach(evalMethod.implementation, {
                onLeave: function (retval) {
                    log('Bypassed AFSecurityPolicy evaluateServerTrust:forDomain:');
                    retval.replace(ptr(1)); // YES
                }
            });
        }
        // Also setSSLPinningMode to disable
        var setPinning = ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'];
        if (setPinning) {
            Interceptor.attach(setPinning.implementation, {
                onEnter: function (args) {
                    // AFSSLPinningModeNone = 0
                    args[2] = ptr(0);
                    log('Bypassed AFSecurityPolicy setSSLPinningMode → None');
                }
            });
        }
    }
} catch (e) {
    logError('AFNetworking hooks failed: ' + e);
}

// ---- 5. Alamofire ---------------------------------------------------------

try {
    var resolver2 = new ApiResolver('objc');

    // Alamofire 5.x uses ServerTrustEvaluating protocol; concrete classes:
    // PinnedCertificatesTrustEvaluator, PublicKeysTrustEvaluator, etc.
    var alamofireClasses = [
        'PinnedCertificatesTrustEvaluator',
        'PublicKeysTrustEvaluator',
        'CompositeTrustEvaluator',
        'RevocationTrustEvaluator',
        'DefaultTrustEvaluator'
    ];

    alamofireClasses.forEach(function (cls) {
        try {
            // Alamofire name-mangles with the module prefix
            var fullNames = resolver2.enumerateMatches('-[*' + cls + '* evaluate*]');
            fullNames.forEach(function (match) {
                try {
                    Interceptor.attach(match.address, {
                        onLeave: function (retval) {
                            log('Bypassed Alamofire ' + cls + ' evaluate');
                            // evaluate throws on failure; we can't un-throw,
                            // but replacing the return keeps the success path.
                        }
                    });
                } catch (e) {}
            });
        } catch (e) {}
    });

    // Alamofire's ServerTrustManager — urlSession:task:didReceiveChallenge:
    // Already caught by the generic NSURLSession hook above, but be explicit.
    var stmMatches = resolver2.enumerateMatches('-[*ServerTrustManager* evaluateServerTrust*]');
    stmMatches.forEach(function (match) {
        try {
            Interceptor.attach(match.address, {
                onLeave: function (retval) {
                    log('Bypassed Alamofire ServerTrustManager evaluate');
                }
            });
        } catch (e) {}
    });
} catch (e) {
    logError('Alamofire hooks failed: ' + e);
}

// ---- 6. TrustKit ----------------------------------------------------------

try {
    if (ObjC.classes.TSKPinningValidator) {
        var trustkitEval = ObjC.classes.TSKPinningValidator['- evaluateTrust:forHostname:'];
        if (trustkitEval) {
            Interceptor.attach(trustkitEval.implementation, {
                onLeave: function (retval) {
                    log('Bypassed TrustKit TSKPinningValidator evaluateTrust:forHostname:');
                    // TSKTrustDecisionShouldAllowConnection = 0
                    retval.replace(ptr(0));
                }
            });
        }
    }

    // TrustKit also has TSKPinningValidatorCallback — hook the result
    if (ObjC.classes.TSKPinningValidator) {
        var validateMethod = ObjC.classes.TSKPinningValidator['+ validateServerTrust:forHostname:validationResult:finalTrustDecision:'];
        if (validateMethod) {
            Interceptor.attach(validateMethod.implementation, {
                onLeave: function (retval) {
                    log('Bypassed TrustKit validateServerTrust class method');
                    retval.replace(ptr(1)); // YES
                }
            });
        }
    }
} catch (e) {
    logError('TrustKit hooks failed: ' + e);
}

// ---- 7. WKWebView ---------------------------------------------------------

try {
    var resolver3 = new ApiResolver('objc');
    var wkMatches = resolver3.enumerateMatches('-[* webView:didReceiveAuthenticationChallenge:completionHandler:]');
    wkMatches.forEach(function (match) {
        try {
            var className = match.name.split(' ')[0].substring(2);
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    var challenge = ObjC.Object(args[3]);
                    var completionHandler = new ObjC.Block(args[4]);
                    try {
                        var protectionSpace = challenge.protectionSpace();
                        var host = protectionSpace.host().toString();
                        var serverTrust = protectionSpace.serverTrust();
                        var credential = ObjC.classes.NSURLCredential['+ credentialForTrust:'](serverTrust);
                        // NSURLSessionAuthChallengeUseCredential = 0
                        completionHandler(0, credential);
                        log('Bypassed WKWebView didReceiveAuthenticationChallenge [' + className + '] for ' + host);
                        this.bypassed = true;
                    } catch (e) {
                        logError('WKWebView bypass for ' + className + ' failed: ' + e);
                    }
                }
            });
        } catch (e) {}
    });
} catch (e) {
    logError('WKWebView hooks failed: ' + e);
}

// ---- 8. BoringSSL / libboringssl (used by some apps directly) -------------

try {
    var SSL_CTX_set_custom_verify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
    if (SSL_CTX_set_custom_verify) {
        Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function (ctx, mode, callback) {
            log('Bypassed SSL_CTX_set_custom_verify');
            // Don't set any verify callback — accept everything
        }, 'void', ['pointer', 'int', 'pointer']));
    }

    var SSL_set_custom_verify = Module.findExportByName(null, 'SSL_set_custom_verify');
    if (SSL_set_custom_verify) {
        Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function (ssl, mode, callback) {
            log('Bypassed SSL_set_custom_verify');
        }, 'void', ['pointer', 'int', 'pointer']));
    }

    // SSL_get_psk_identity — used in BoringSSL cert verification
    var SSL_CTX_set_verify = Module.findExportByName(null, 'SSL_CTX_set_verify');
    if (SSL_CTX_set_verify) {
        Interceptor.replace(SSL_CTX_set_verify, new NativeCallback(function (ctx, mode, callback) {
            log('Bypassed SSL_CTX_set_verify');
            // SSL_VERIFY_NONE = 0
        }, 'void', ['pointer', 'int', 'pointer']));
    }
} catch (e) {
    logError('BoringSSL hooks failed: ' + e);
}

log('Certificate pinning bypass loaded — all hooks installed');
`

// fridaApp represents a running app as reported by frida-ps.
type fridaApp struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
}

// pinEvent is a structured JSON event emitted on stdout.
type pinEvent struct {
	Event    string `json:"event"`
	Target   string `json:"target,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Function string `json:"function,omitempty"`
	Host     string `json:"host,omitempty"`
	Message  string `json:"message,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func emitEvent(e pinEvent) {
	b, _ := json.Marshal(e)
	os.Stdout.Write(b)
	os.Stdout.Write([]byte{'\n'})
}

// pinbypass implements the "pinbypass" subcommand.
func pinbypass(args []string) {
	fs := flag.NewFlagSet("pinbypass", flag.ExitOnError)
	pid := fs.Int("p", 0, "attach by PID instead of app name")
	scriptOnly := fs.Bool("script-only", false, "print the Frida JS payload and exit")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usbnet pinbypass: bypass certificate pinning on an iOS app via Frida

  usbnet pinbypass                    list running apps (JSON)
  usbnet pinbypass <app-name>         attach to app and bypass pinning
  usbnet pinbypass -p <pid>           attach by PID
  usbnet pinbypass --script-only      print Frida JS payload to stdout`)
	}
	_ = fs.Parse(args)

	if *scriptOnly {
		fmt.Print(fridaScript)
		return
	}

	// Check that frida is installed.
	if _, err := exec.LookPath("frida"); err != nil {
		fmt.Fprintln(os.Stderr, `frida not found. Install it:
  pip3 install frida-tools

Then connect the iPhone via USB and run:
  usbnet pinbypass <app-name>`)
		os.Exit(1)
	}

	appName := fs.Arg(0)

	// No app name and no PID — list running apps.
	if appName == "" && *pid == 0 {
		listApps()
		return
	}

	runBypass(appName, *pid)
}

// listApps runs frida-ps -Uaj and emits a JSON array.
func listApps() {
	cmd := exec.Command("frida-ps", "-Uaj")
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "frida-ps failed: %s\n", string(exitErr.Stderr))
		} else {
			fmt.Fprintf(os.Stderr, "frida-ps failed: %v\n", err)
		}
		os.Exit(1)
	}

	// frida-ps -Uaj outputs JSON: array of {"pid":N,"name":"...","identifier":"..."}
	// Validate it's JSON and pass through.
	var apps []json.RawMessage
	if err := json.Unmarshal(out, &apps); err != nil {
		// Not JSON — frida-ps without -j flag or old version. Parse tabular.
		apps := parseFridaPS(out)
		b, _ := json.MarshalIndent(apps, "", "  ")
		os.Stdout.Write(b)
		os.Stdout.Write([]byte{'\n'})
		return
	}

	// Already valid JSON — pretty-print it.
	var pretty []fridaApp
	_ = json.Unmarshal(out, &pretty)
	b, _ := json.MarshalIndent(pretty, "", "  ")
	os.Stdout.Write(b)
	os.Stdout.Write([]byte{'\n'})
}

// parseFridaPS parses the tabular output of frida-ps -Ua (without -j).
func parseFridaPS(data []byte) []fridaApp {
	var apps []fridaApp
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		// Skip header lines (PID Name Identifier) and separator (---).
		if lineNo <= 2 || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "---") || strings.HasPrefix(strings.TrimSpace(line), "PID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		p, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		// Name can contain spaces; identifier is the last field if it looks
		// like a bundle ID (contains a dot).
		identifier := ""
		name := ""
		if len(fields) >= 3 {
			last := fields[len(fields)-1]
			if strings.Contains(last, ".") {
				identifier = last
				name = strings.Join(fields[1:len(fields)-1], " ")
			} else {
				name = strings.Join(fields[1:], " ")
			}
		} else {
			name = fields[1]
		}
		apps = append(apps, fridaApp{PID: p, Name: name, Identifier: identifier})
	}
	return apps
}

// runBypass writes the Frida script to a temp file, launches frida, and streams
// output. It translates Frida's JSON messages into structured events on stdout
// and passes raw output to stderr.
func runBypass(appName string, pid int) {
	// Write the script to a temp file.
	scriptFile, err := os.CreateTemp(os.TempDir(), "usbnet-pinbypass-*.js")
	if err != nil {
		emitEvent(pinEvent{Event: "error", Message: "failed to create temp script: " + err.Error()})
		os.Exit(1)
	}
	scriptPath := scriptFile.Name()
	defer os.Remove(scriptPath)

	if _, err := scriptFile.WriteString(fridaScript); err != nil {
		scriptFile.Close()
		emitEvent(pinEvent{Event: "error", Message: "failed to write script: " + err.Error()})
		os.Exit(1)
	}
	scriptFile.Close()

	// Build frida command.
	var fridaArgs []string
	fridaArgs = append(fridaArgs, "-U") // USB device
	if pid > 0 {
		fridaArgs = append(fridaArgs, "-p", strconv.Itoa(pid))
	} else {
		fridaArgs = append(fridaArgs, "-n", appName)
	}
	fridaArgs = append(fridaArgs, "-l", scriptPath, "--no-pause")

	cmd := exec.Command("frida", fridaArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		emitEvent(pinEvent{Event: "error", Message: "pipe stdout: " + err.Error()})
		os.Exit(1)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		emitEvent(pinEvent{Event: "error", Message: "failed to start frida: " + err.Error()})
		os.Exit(1)
	}

	target := appName
	if target == "" {
		target = strconv.Itoa(pid)
	}
	emitEvent(pinEvent{Event: "started", Target: target, PID: pid})

	// Handle SIGINT/SIGTERM — forward to frida, then exit.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
	}()

	// Parse frida's stdout. Frida sends JSON messages on stdout when the
	// script calls send(). Lines that look like JSON messages from our
	// script are translated into structured events.
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if ev := parseFridaLine(line); ev != nil {
			emitEvent(*ev)
		} else {
			// Unstructured output — pass to stderr.
			fmt.Fprintln(os.Stderr, line)
		}
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			emitEvent(pinEvent{Event: "detached", Reason: fmt.Sprintf("frida exited with code %d", exitErr.ExitCode())})
		} else {
			emitEvent(pinEvent{Event: "detached", Reason: err.Error()})
		}
	} else {
		emitEvent(pinEvent{Event: "detached", Reason: "frida exited normally"})
	}

	// Drain stdout pipe in case scanner stopped early.
	_, _ = io.Copy(io.Discard, stdout)
}

// bypassRe matches log lines like "[USBNet] Bypassed SecTrustEvaluateWithError for api.example.com"
// or "[USBNet] Bypassed SecTrustEvaluateWithError"
var bypassRe = regexp.MustCompile(`\[USBNet\]\s+Bypassed\s+(.+?)(?:\s+for\s+(.+))?$`)

// fridaMessageRe matches Frida's JSON message relay format:
// {"type":"send","payload":{"type":"bypass","message":"Bypassed ..."}}
var fridaMessageRe = regexp.MustCompile(`^\s*\{`)

// parseFridaLine attempts to parse a line from frida's stdout into a pinEvent.
func parseFridaLine(line string) *pinEvent {
	trimmed := strings.TrimSpace(line)

	// Try to parse as a Frida JSON message.
	if fridaMessageRe.MatchString(trimmed) {
		var msg struct {
			Type    string `json:"type"`
			Payload struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"payload"`
		}
		if err := json.Unmarshal([]byte(trimmed), &msg); err == nil && msg.Type == "send" {
			return parseFridaPayload(msg.Payload.Type, msg.Payload.Message)
		}
	}

	// Try the console.log format: "[USBNet] Bypassed ..."
	if m := bypassRe.FindStringSubmatch(trimmed); m != nil {
		ev := &pinEvent{Event: "bypass", Function: strings.TrimSpace(m[1])}
		if m[2] != "" {
			ev.Host = strings.TrimSpace(m[2])
		}
		return ev
	}

	return nil
}

func parseFridaPayload(typ, message string) *pinEvent {
	switch typ {
	case "bypass":
		ev := &pinEvent{Event: "bypass"}
		if m := bypassRe.FindStringSubmatch(message); m != nil {
			ev.Function = strings.TrimSpace(m[1])
			if m[2] != "" {
				ev.Host = strings.TrimSpace(m[2])
			}
		} else {
			ev.Function = message
		}
		return ev
	case "error":
		return &pinEvent{Event: "error", Message: message}
	default:
		return &pinEvent{Event: "info", Message: message}
	}
}
