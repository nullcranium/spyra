import Java from 'frida-java-bridge';

declare const Module: any;
declare const Interceptor: any;
declare const Process: any;

console.log('[*] Script loaded.');

Java.perform(() => {
    console.log('[*] Java bridge ready, installing hooks..');
    try {
        const URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (url: string) {
            console.log(`[NETWORK] URL created: ${url}`);
            send({ type: 'network', action: 'url_init', url: url, timestamp: Date.now() });
            return this.$init(url);
        };
    } catch (e) {
        console.log(`[-] Failed to hook URL: ${e}`);
    }

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
    } catch (e) {
        console.log(`[-] Failed to hook HttpURLConnection: ${e}`);
    }

    try {
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

        HttpsURLConnection.getInputStream.implementation = function () {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            console.log(`[HTTPS] ${method} ${url}`);
            send({ type: 'network', action: 'https_request', method: method, url: url, timestamp: Date.now() });
            return this.getInputStream();
        };
    } catch (e) {
        console.log(`[-] Failed to hook HttpsURLConnection: ${e}`);
    }
    try {
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const Request = Java.use('okhttp3.Request');
        const Response = Java.use('okhttp3.Response');

        OkHttpClient.newCall.implementation = function (request: any) {
            const url = request.url().toString();
            const method = request.method();
            const headers = request.headers();

            console.log(`[OKHTTP] ${method} ${url}`);

            const headerMap: any = {};
            const headerNames = headers.names();
            const iterator = headerNames.iterator();
            while (iterator.hasNext()) {
                const name = iterator.next();
                headerMap[name] = headers.get(name);
            }

            send({
                type: 'network',
                action: 'okhttp_request',
                method: method,
                url: url,
                headers: headerMap,
                timestamp: Date.now()
            });

            return this.newCall(request);
        };
    } catch (e) {
        console.log(`[-] Failed to hook OkHttp3: ${e}`);
    }

    try {
        const ResponseBody = Java.use('okhttp3.ResponseBody');

        ResponseBody.string.implementation = function () {
            const body = this.string();
            const preview = body.length > 500 ? body.substring(0, 500) + '...' : body;
            console.log(`[OKHTTP] Response body: ${preview}`);
            send({
                type: 'network',
                action: 'okhttp_response',
                body: preview,
                size: body.length,
                timestamp: Date.now()
            });
            return body;
        };
    } catch (e) {
        console.log(`[-] Failed to hook OkHttp ResponseBody: ${e}`);
    }

    try {
        const Socket = Java.use('java.net.Socket');

        Socket.$init.overload('java.lang.String', 'int').implementation = function (host: string, port: number) {
            console.log(`[SOCKET] Connecting to ${host}:${port}`);
            send({ type: 'network', action: 'socket_connect', host: host, port: port, timestamp: Date.now() });
            return this.$init(host, port);
        };
    } catch (e) {
        console.log(`[-] Failed to hook Socket: ${e}`);
    }

    try {
        const File = Java.use('java.io.File');

        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            const result = this.exists();
            console.log(`[FILE] exists("${path}") = ${result}`);
            send({ type: 'file', action: 'exists', path: path, result: result, timestamp: Date.now() });
            return result;
        };

        File.delete.implementation = function () {
            const path = this.getAbsolutePath();
            const result = this.delete();
            console.log(`[FILE] delete("${path}") = ${result}`);
            send({ type: 'file', action: 'delete', path: path, result: result, timestamp: Date.now() });
            return result;
        };
    } catch (e) {
        console.log(`[-] Failed to hook File: ${e}`);
    }

    try {
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.lang.String').implementation = function (path: string) {
            console.log(`[FILE] FileOutputStream: ${path}`);
            send({ type: 'file', action: 'write', path: path, timestamp: Date.now() });
            return this.$init(path);
        };
    } catch (e) {
        console.log(`[-] Failed to hook FileOutputStream: ${e}`);
    }

    try {
        const SharedPreferences = Java.use('android.content.SharedPreferences');
        const Editor = Java.use('android.content.SharedPreferences$Editor');

        Editor.putString.implementation = function (key: string, value: string) {
            console.log(`[PREFS] putString("${key}", "${value}")`);
            send({ type: 'prefs', action: 'put', key: key, value: value, timestamp: Date.now() });
            return this.putString(key, value);
        };
    } catch (e) {
        console.log(`[-] Failed to hook SharedPreferences: ${e}`);
    }

    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation: string) {
            console.log(`[CRYPTO] Cipher.getInstance("${transformation}")`);
            send({ type: 'crypto', action: 'get_cipher', transformation: transformation, timestamp: Date.now() });
            return this.getInstance(transformation);
        };
    } catch (e) {
        console.log(`[-] Failed to hook Cipher: ${e}`);
    }

    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm: string) {
            console.log(`[CRYPTO] MessageDigest.getInstance("${algorithm}")`);
            send({ type: 'crypto', action: 'get_digest', algorithm: algorithm, timestamp: Date.now() });
            return this.getInstance(algorithm);
        };
    } catch (e) {
        console.log(`[-] Failed to hook MessageDigest: ${e}`);
    }

    try {
        const TelephonyManager = Java.use('android.telephony.TelephonyManager');

        TelephonyManager.getDeviceId.overload().implementation = function () {
            const deviceId = this.getDeviceId();
            console.log(`[SYSTEM] getDeviceId() = ${deviceId}`);
            send({ type: 'system', action: 'get_device_id', value: deviceId, timestamp: Date.now() });
            return deviceId;
        };
    } catch (e) {
        console.log(`[-] Failed to hook TelephonyManager: ${e}`);
    }

    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd: string) {
            console.log(`[EXEC] Runtime.exec("${cmd}")`);
            send({ type: 'exec', action: 'runtime_exec', command: cmd, timestamp: Date.now() });
            return this.exec(cmd);
        };
    } catch (e) {
        console.log(`[-] Failed to hook Runtime: ${e}`);
    }

    try {
        const WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url: string) {
            console.log(`[WEBVIEW] loadUrl("${url}")`);
            send({ type: 'webview', action: 'load_url', url: url, timestamp: Date.now() });
            return this.loadUrl(url);
        };
    } catch (e) {
        console.log(`[-] Failed to hook WebView: ${e}`);
    }

    try {
        const Intent = Java.use('android.content.Intent');
        Intent.$init.overload('java.lang.String').implementation = function (action: string) {
            console.log(`[INTENT] new Intent("${action}")`);
            send({ type: 'intent', action: 'create', intent_action: action, timestamp: Date.now() });
            return this.$init(action);
        };
    } catch (e) {
        console.log(`[-] Failed to hook Intent: ${e}`);
    }

    console.log('[*] ========================================');
    console.log('[*] All API hooks installed successfully!');
    console.log('[*] Monitoring active - interact with app');
    console.log('[*] ========================================');
});

console.log('[*] Installing native hooks..');

const libc_functions = ['fopen', 'open', 'read', 'write', 'connect', 'send', 'recv'];
for (const funcName of libc_functions) {
    const funcPtr = Module.findExportByName('libc.so', funcName);
    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function (args: any) {
                if (funcName === 'fopen' || funcName === 'open') {
                    try {
                        const path = args[0].readUtf8String();
                        if (path && !path.includes('/dev/') && !path.includes('/proc/')) {
                            console.log(`[NATIVE] ${funcName}("${path}")`);
                            send({ type: 'native', func: funcName, path: path, timestamp: Date.now() });
                        }
                    } catch (e) {
                        // Ignore read errors
                    }
                }
            }
        });
    }
}

console.log('[*] Native hooks installed');
console.log('[*] API Interceptor ready!');
