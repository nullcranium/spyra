// auto-generated native hooks
// compatible with Frida 17+

import Java from 'frida-java-bridge';

declare const Module: any;
declare const Interceptor: any;
declare const Process: any;
declare const send: any;

console.log('[*] Detected frameworks: native');

console.log('[*] Installing Java network hooks.');
Java.perform(() => {
    try {
        const HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getInputStream.implementation = function () {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            console.log(`[HTTP] ${method} ${url}`);
            send({ type: 'network', action: 'http_request', method: method, url: url, timestamp: Date.now() });
            return this.getInputStream();
        };
        HttpURLConnection.getOutputStream.implementation = function () {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            console.log(`[HTTP] ${method} ${url} (with body)`);
            send({ type: 'network', action: 'http_request_body', method: method, url: url, timestamp: Date.now() });
            return this.getOutputStream();
        };
        console.log('[✓] HttpURLConnection hooks');
    } catch (e) {
        console.log(`[-] HttpURLConnection hooks failed: ${e}`);
    }
    
    try {
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function (request: any) {
            const url = request.url().toString();
            const method = request.method();
            console.log(`[OKHTTP] ${method} ${url}`);
            send({ type: 'network', action: 'okhttp_request', method: method, url: url, timestamp: Date.now() });
            return this.newCall(request);
        };
        console.log('[✓] OkHttp hooks');
    } catch (e) {
        console.log(`[-] OkHttp hooks failed: ${e}`);
    }
    
    try {
        const Socket = Java.use('java.net.Socket');
        Socket.$init.overload('java.lang.String', 'int').implementation = function (host: string, port: number) {
            console.log(`[SOCKET] Connecting to ${host}:${port}`);
            send({ type: 'network', action: 'socket_connect', host: host, port: port, timestamp: Date.now() });
            return this.$init(host, port);
        };
        console.log('[✓] Socket hooks');
    } catch (e) {
        console.log(`[-] Socket hooks failed: ${e}`);
    }
});

console.log('[*] Installing native hooks.');

const libc = Process.getModuleByName('libc.so');
if (libc) {
    // File operations
    const file_funcs = ['fopen', 'open'];
    for (const funcName of file_funcs) {
        const funcPtr = libc.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    try {
                        const path = args[0].readUtf8String();
                        if (path && !path.includes('/dev/') && !path.includes('/proc/') && !path.includes('/sys/')) {
                            // console.log(`[native] ${funcName}("${path}")`);
                            send({type: 'native', func: funcName, path: path, timestamp: Date.now()});
                        }
                    } catch (e) {}
                }
            });
        }
    }

    const connectPtr = libc.findExportByName('connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args: any) {
                this.sock = args[0].toInt32();
                const sockaddr = args[1];
                const socklen = args[2].toInt32();
                try {
                    const family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        const ip = sockaddr.add(4).readU8() + '.' +
                                   sockaddr.add(5).readU8() + '.' +
                                   sockaddr.add(6).readU8() + '.' +
                                   sockaddr.add(7).readU8();
                        console.log(`[native] connect(${ip}:${port})`);
                        send({type: 'network', action: 'connect', ip: ip, port: port, timestamp: Date.now()});
                    } else if (family === 10) { // AF_INET6
                        const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        let ip = "";
                        for (let i = 0; i < 16; i += 2) {
                             const b1 = sockaddr.add(8 + i).readU8();
                             const b2 = sockaddr.add(8 + i + 1).readU8();
                             if (i > 0) ip += ":";
                             ip += ((b1 << 8) | b2).toString(16);
                        }
                        console.log(`[native] connect([${ip}]:${port})`);
                        send({type: 'network', action: 'connect', ip: ip, port: port, timestamp: Date.now()});
                    }
                } catch (e) {}
            }
        });
    }

    // Network: send/recv
    const net_funcs = ['send', 'recv', 'sendto', 'recvfrom'];
    for (const funcName of net_funcs) {
        const funcPtr = libc.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    this.len = args[2].toInt32();
                },
                onLeave: function(retval: any) {
                    const ret = retval.toInt32();
                    if (ret > 0) {
                        // console.log(`[native] ${funcName} (${ret} bytes)`);
                        send({type: 'network', action: funcName, bytes: ret, timestamp: Date.now()});
                    }
                }
            });
        }
    }
}

// SSL hooks
const ssl_functions = ['SSL_read', 'SSL_write', 'SSL_connect'];
const libssl = Process.getModuleByName('libssl.so');
if (libssl) {
    for (const funcName of ssl_functions) {
        const funcPtr = libssl.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    // console.log(`[ssl] ${funcName} called`);
                    send({type: 'ssl', func: funcName, timestamp: Date.now()});
                }
            });
        }
    }
}

// JNI RegisterNatives hook
const libart = Process.findModuleByName('libart.so');
if (libart) {
    const RegisterNatives = libart.enumerateSymbols().find((s: any) => s.name.includes('RegisterNatives'));
    if (RegisterNatives) {
        Interceptor.attach(RegisterNatives.address, {
            onEnter: function(args: any) {
                const env = args[0];
                const jclass = args[1];
                const methods = args[2];
                const nMethods = args[3].toInt32();
                try {
                    console.log(`[JNI] RegisterNatives count=${nMethods}`);
                    send({type: 'native', action: 'jni_register', count: nMethods, timestamp: Date.now()});
                    for (let i = 0; i < nMethods; i++) {
                        const method = methods.add(i * Process.pointerSize * 3);
                        const name = method.readPointer().readUtf8String();
                        const sig = method.add(Process.pointerSize).readPointer().readUtf8String();
                        const fnPtr = method.add(Process.pointerSize * 2).readPointer();
                        
                        console.log(`  - ${name}${sig} -> ${fnPtr}`);
                        send({
                            type: 'native', 
                            action: 'jni_method_map', 
                            method: name, 
                            sig: sig, 
                            ptr: fnPtr.toString(),
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {
                    console.log(`[JNI] Error in RegisterNatives hook: ${e}`);
                }
            }
        });
    }
}

console.log('[*] Native hooks installed. Interact with the app to see activity.');
