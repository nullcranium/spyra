// auto-generated native hooks
// compatible with Frida 17+

import {} from 'frida-java-bridge';

declare const Module: any;
declare const Interceptor: any;
declare const send: any;

console.log('[*] Detected frameworks: native');

console.log('[*] Installing native hooks.');

const libc_functions = ['fopen', 'open', 'read', 'write', 'connect', 'send', 'recv'];
for (const funcName of libc_functions) {
    const funcPtr = Module.findExportByName('libc.so', funcName);
    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args: any) {
                if (funcName === 'fopen' || funcName === 'open') {
                    try {
                        const path = args[0].readUtf8String();
                        if (path && !path.includes('/dev/') && !path.includes('/proc/')) {
                            console.log(`[native] ${funcName}("${path}")`);
                            send({type: 'native', func: funcName, path: path, timestamp: Date.now()});
                        }
                    } catch (e) {
                        // ignore
                    }
                }
            }
        });
    }
}

const ssl_functions = ['SSL_read', 'SSL_write', 'SSL_connect'];
for (const funcName of ssl_functions) {
    const funcPtr = Module.findExportByName('libssl.so', funcName);
    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args: any) {
                console.log(`[ssl] ${funcName} called`);
                send({type: 'ssl', func: funcName, timestamp: Date.now()});
            }
        });
    }
}

console.log('[*] try to interact with the app to see results');
