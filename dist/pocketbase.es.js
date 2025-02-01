/**
 * ClientResponseError is a custom Error class that is intended to wrap
 * and normalize any error thrown by `Client.send()`.
 */
class ClientResponseError extends Error {
    constructor(errData) {
        super("ClientResponseError");
        this.url = "";
        this.status = 0;
        this.response = {};
        this.isAbort = false;
        this.originalError = null;
        // Set the prototype explicitly.
        // https://github.com/Microsoft/TypeScript-wiki/blob/main/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
        Object.setPrototypeOf(this, ClientResponseError.prototype);
        if (errData !== null && typeof errData === "object") {
            this.url = typeof errData.url === "string" ? errData.url : "";
            this.status = typeof errData.status === "number" ? errData.status : 0;
            this.isAbort = !!errData.isAbort;
            this.originalError = errData.originalError;
            if (errData.response !== null && typeof errData.response === "object") {
                this.response = errData.response;
            }
            else if (errData.data !== null && typeof errData.data === "object") {
                this.response = errData.data;
            }
            else {
                this.response = {};
            }
        }
        if (!this.originalError && !(errData instanceof ClientResponseError)) {
            this.originalError = errData;
        }
        if (typeof DOMException !== "undefined" && errData instanceof DOMException) {
            this.isAbort = true;
        }
        this.name = "ClientResponseError " + this.status;
        this.message = this.response?.message;
        if (!this.message) {
            if (this.originalError?.cause?.message?.includes("ECONNREFUSED ::1")) {
                this.message =
                    "Failed to connect to the PocketBase server. Try changing the SDK URL from localhost to 127.0.0.1 (https://github.com/pocketbase/js-sdk/issues/21).";
            }
            else {
                this.message = "Something went wrong while processing your request.";
            }
        }
    }
    /**
     * Alias for `this.response` for backward compatibility.
     */
    get data() {
        return this.response;
    }
    /**
     * Make a POJO's copy of the current error class instance.
     * @see https://github.com/vuex-orm/vuex-orm/issues/255
     */
    toJSON() {
        return { ...this };
    }
}

/**
 * -------------------------------------------------------------------
 * Simple cookie parse and serialize utilities mostly based on the
 * node module https://github.com/jshttp/cookie.
 * -------------------------------------------------------------------
 */
/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */
const fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
/**
 * Parses the given cookie header string into an object
 * The object has the various cookies as keys(names) => values
 */
function cookieParse(str, options) {
    const result = {};
    if (typeof str !== "string") {
        return result;
    }
    const opt = Object.assign({}, options || {});
    const decode = opt.decode || defaultDecode;
    let index = 0;
    while (index < str.length) {
        const eqIdx = str.indexOf("=", index);
        // no more cookie pairs
        if (eqIdx === -1) {
            break;
        }
        let endIdx = str.indexOf(";", index);
        if (endIdx === -1) {
            endIdx = str.length;
        }
        else if (endIdx < eqIdx) {
            // backtrack on prior semicolon
            index = str.lastIndexOf(";", eqIdx - 1) + 1;
            continue;
        }
        const key = str.slice(index, eqIdx).trim();
        // only assign once
        if (undefined === result[key]) {
            let val = str.slice(eqIdx + 1, endIdx).trim();
            // quoted values
            if (val.charCodeAt(0) === 0x22) {
                val = val.slice(1, -1);
            }
            try {
                result[key] = decode(val);
            }
            catch (_) {
                result[key] = val; // no decoding
            }
        }
        index = endIdx + 1;
    }
    return result;
}
/**
 * Serialize data into a cookie header.
 *
 * Serialize the a name value pair into a cookie string suitable for
 * http headers. An optional options object specified cookie parameters.
 *
 * ```js
 * cookieSerialize('foo', 'bar', { httpOnly: true }) // "foo=bar; httpOnly"
 * ```
 */
function cookieSerialize(name, val, options) {
    const opt = Object.assign({}, options || {});
    const encode = opt.encode || defaultEncode;
    if (!fieldContentRegExp.test(name)) {
        throw new TypeError("argument name is invalid");
    }
    const value = encode(val);
    if (value && !fieldContentRegExp.test(value)) {
        throw new TypeError("argument val is invalid");
    }
    let result = name + "=" + value;
    if (opt.maxAge != null) {
        const maxAge = opt.maxAge - 0;
        if (isNaN(maxAge) || !isFinite(maxAge)) {
            throw new TypeError("option maxAge is invalid");
        }
        result += "; Max-Age=" + Math.floor(maxAge);
    }
    if (opt.domain) {
        if (!fieldContentRegExp.test(opt.domain)) {
            throw new TypeError("option domain is invalid");
        }
        result += "; Domain=" + opt.domain;
    }
    if (opt.path) {
        if (!fieldContentRegExp.test(opt.path)) {
            throw new TypeError("option path is invalid");
        }
        result += "; Path=" + opt.path;
    }
    if (opt.expires) {
        if (!isDate(opt.expires) || isNaN(opt.expires.valueOf())) {
            throw new TypeError("option expires is invalid");
        }
        result += "; Expires=" + opt.expires.toUTCString();
    }
    if (opt.httpOnly) {
        result += "; HttpOnly";
    }
    if (opt.secure) {
        result += "; Secure";
    }
    if (opt.priority) {
        const priority = typeof opt.priority === "string" ? opt.priority.toLowerCase() : opt.priority;
        switch (priority) {
            case "low":
                result += "; Priority=Low";
                break;
            case "medium":
                result += "; Priority=Medium";
                break;
            case "high":
                result += "; Priority=High";
                break;
            default:
                throw new TypeError("option priority is invalid");
        }
    }
    if (opt.sameSite) {
        const sameSite = typeof opt.sameSite === "string" ? opt.sameSite.toLowerCase() : opt.sameSite;
        switch (sameSite) {
            case true:
                result += "; SameSite=Strict";
                break;
            case "lax":
                result += "; SameSite=Lax";
                break;
            case "strict":
                result += "; SameSite=Strict";
                break;
            case "none":
                result += "; SameSite=None";
                break;
            default:
                throw new TypeError("option sameSite is invalid");
        }
    }
    return result;
}
/**
 * Default URL-decode string value function.
 * Optimized to skip native call when no `%`.
 */
function defaultDecode(val) {
    return val.indexOf("%") !== -1 ? decodeURIComponent(val) : val;
}
/**
 * Default URL-encode value function.
 */
function defaultEncode(val) {
    return encodeURIComponent(val);
}
/**
 * Determines if value is a Date.
 */
function isDate(val) {
    return Object.prototype.toString.call(val) === "[object Date]" || val instanceof Date;
}

let atobPolyfill;
if (typeof atob === "function") {
    atobPolyfill = atob;
}
else {
    /**
     * The code was extracted from:
     * https://github.com/davidchambers/Base64.js
     */
    atobPolyfill = (input) => {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let str = String(input).replace(/=+$/, "");
        if (str.length % 4 == 1) {
            throw new Error("'atob' failed: The string to be decoded is not correctly encoded.");
        }
        for (
        // initialize result and counters
        var bc = 0, bs, buffer, idx = 0, output = ""; 
        // get next character
        (buffer = str.charAt(idx++)); 
        // character found in table? initialize bit storage and add its ascii value;
        ~buffer &&
            ((bs = bc % 4 ? bs * 64 + buffer : buffer),
                // and if not first of each 4 characters,
                // convert the first 8 bits to one ascii character
                bc++ % 4)
            ? (output += String.fromCharCode(255 & (bs >> ((-2 * bc) & 6))))
            : 0) {
            // try to find character in table (0-63, not found => -1)
            buffer = chars.indexOf(buffer);
        }
        return output;
    };
}
/**
 * Returns JWT token's payload data.
 */
function getTokenPayload(token) {
    if (token) {
        try {
            const encodedPayload = decodeURIComponent(atobPolyfill(token.split(".")[1])
                .split("")
                .map(function (c) {
                return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
            })
                .join(""));
            return JSON.parse(encodedPayload) || {};
        }
        catch (e) { }
    }
    return {};
}
/**
 * Checks whether a JWT token is expired or not.
 * Tokens without `exp` payload key are considered valid.
 * Tokens with empty payload (eg. invalid token strings) are considered expired.
 *
 * @param token The token to check.
 * @param [expirationThreshold] Time in seconds that will be subtracted from the token `exp` property.
 */
function isTokenExpired(token, expirationThreshold = 0) {
    let payload = getTokenPayload(token);
    if (Object.keys(payload).length > 0 &&
        (!payload.exp || payload.exp - expirationThreshold > Date.now() / 1000)) {
        return false;
    }
    return true;
}

const defaultCookieKey = "pb_auth";
/**
 * Base AuthStore class that stores the auth state in runtime memory (aka. only for the duration of the store instane).
 *
 * Usually you wouldn't use it directly and instead use the builtin LocalAuthStore, AsyncAuthStore
 * or extend it with your own custom implementation.
 */
class BaseAuthStore {
    constructor() {
        this.baseToken = "";
        this.baseModel = null;
        this._onChangeCallbacks = [];
    }
    /**
     * Retrieves the stored token (if any).
     */
    get token() {
        return this.baseToken;
    }
    /**
     * Retrieves the stored model data (if any).
     */
    get record() {
        return this.baseModel;
    }
    /**
     * @deprecated use `record` instead.
     */
    get model() {
        return this.baseModel;
    }
    /**
     * Loosely checks if the store has valid token (aka. existing and unexpired exp claim).
     */
    get isValid() {
        return !isTokenExpired(this.token);
    }
    /**
     * Loosely checks whether the currently loaded store state is for superuser.
     *
     * Alternatively you can also compare directly `pb.authStore.record?.collectionName`.
     */
    get isSuperuser() {
        let payload = getTokenPayload(this.token);
        return (payload.type == "auth" &&
            (this.record?.collectionName == "_superusers" ||
                // fallback in case the record field is not populated and assuming
                // that the collection crc32 checksum id wasn't manually changed
                (!this.record?.collectionName &&
                    payload.collectionId == "pbc_3142635823")));
    }
    /**
     * @deprecated use `isSuperuser` instead or simply check the record.collectionName property.
     */
    get isAdmin() {
        console.warn("Please replace pb.authStore.isAdmin with pb.authStore.isSuperuser OR simply check the value of pb.authStore.record?.collectionName");
        return this.isSuperuser;
    }
    /**
     * @deprecated use `!isSuperuser` instead or simply check the record.collectionName property.
     */
    get isAuthRecord() {
        console.warn("Please replace pb.authStore.isAuthRecord with !pb.authStore.isSuperuser OR simply check the value of pb.authStore.record?.collectionName");
        return getTokenPayload(this.token).type == "auth" && !this.isSuperuser;
    }
    /**
     * Saves the provided new token and model data in the auth store.
     */
    save(token, record) {
        this.baseToken = token || "";
        this.baseModel = record || null;
        this.triggerChange();
    }
    /**
     * Removes the stored token and model data form the auth store.
     */
    clear() {
        this.baseToken = "";
        this.baseModel = null;
        this.triggerChange();
    }
    /**
     * Parses the provided cookie string and updates the store state
     * with the cookie's token and model data.
     *
     * NB! This function doesn't validate the token or its data.
     * Usually this isn't a concern if you are interacting only with the
     * PocketBase API because it has the proper server-side security checks in place,
     * but if you are using the store `isValid` state for permission controls
     * in a node server (eg. SSR), then it is recommended to call `authRefresh()`
     * after loading the cookie to ensure an up-to-date token and model state.
     * For example:
     *
     * ```js
     * pb.authStore.loadFromCookie("cookie string...");
     *
     * try {
     *     // get an up-to-date auth store state by veryfing and refreshing the loaded auth model (if any)
     *     pb.authStore.isValid && await pb.collection('users').authRefresh();
     * } catch (_) {
     *     // clear the auth store on failed refresh
     *     pb.authStore.clear();
     * }
     * ```
     */
    loadFromCookie(cookie, key = defaultCookieKey) {
        const rawData = cookieParse(cookie || "")[key] || "";
        let data = {};
        try {
            data = JSON.parse(rawData);
            // normalize
            if (typeof data === null || typeof data !== "object" || Array.isArray(data)) {
                data = {};
            }
        }
        catch (_) { }
        this.save(data.token || "", data.record || data.model || null);
    }
    /**
     * Exports the current store state as cookie string.
     *
     * By default the following optional attributes are added:
     * - Secure
     * - HttpOnly
     * - SameSite=Strict
     * - Path=/
     * - Expires={the token expiration date}
     *
     * NB! If the generated cookie exceeds 4096 bytes, this method will
     * strip the model data to the bare minimum to try to fit within the
     * recommended size in https://www.rfc-editor.org/rfc/rfc6265#section-6.1.
     */
    exportToCookie(options, key = defaultCookieKey) {
        const defaultOptions = {
            secure: true,
            sameSite: true,
            httpOnly: true,
            path: "/",
        };
        // extract the token expiration date
        const payload = getTokenPayload(this.token);
        if (payload?.exp) {
            defaultOptions.expires = new Date(payload.exp * 1000);
        }
        else {
            defaultOptions.expires = new Date("1970-01-01");
        }
        // merge with the user defined options
        options = Object.assign({}, defaultOptions, options);
        const rawData = {
            token: this.token,
            record: this.record ? JSON.parse(JSON.stringify(this.record)) : null,
        };
        let result = cookieSerialize(key, JSON.stringify(rawData), options);
        const resultLength = typeof Blob !== "undefined" ? new Blob([result]).size : result.length;
        // strip down the model data to the bare minimum
        if (rawData.record && resultLength > 4096) {
            rawData.record = { id: rawData.record?.id, email: rawData.record?.email };
            const extraProps = ["collectionId", "collectionName", "verified"];
            for (const prop in this.record) {
                if (extraProps.includes(prop)) {
                    rawData.record[prop] = this.record[prop];
                }
            }
            result = cookieSerialize(key, JSON.stringify(rawData), options);
        }
        return result;
    }
    /**
     * Register a callback function that will be called on store change.
     *
     * You can set the `fireImmediately` argument to true in order to invoke
     * the provided callback right after registration.
     *
     * Returns a removal function that you could call to "unsubscribe" from the changes.
     */
    onChange(callback, fireImmediately = false) {
        this._onChangeCallbacks.push(callback);
        if (fireImmediately) {
            callback(this.token, this.record);
        }
        return () => {
            for (let i = this._onChangeCallbacks.length - 1; i >= 0; i--) {
                if (this._onChangeCallbacks[i] == callback) {
                    delete this._onChangeCallbacks[i]; // removes the function reference
                    this._onChangeCallbacks.splice(i, 1); // reindex the array
                    return;
                }
            }
        };
    }
    triggerChange() {
        for (const callback of this._onChangeCallbacks) {
            callback && callback(this.token, this.record);
        }
    }
}

/**
 * The default token store for browsers with auto fallback
 * to runtime/memory if local storage is undefined (e.g. in node env).
 */
class LocalAuthStore extends BaseAuthStore {
    constructor(storageKey = "pocketbase_auth") {
        super();
        this.storageFallback = {};
        this.storageKey = storageKey;
        this._bindStorageEvent();
    }
    /**
     * @inheritdoc
     */
    get token() {
        const data = this._storageGet(this.storageKey) || {};
        return data.token || "";
    }
    /**
     * @inheritdoc
     */
    get record() {
        const data = this._storageGet(this.storageKey) || {};
        return data.record || data.model || null;
    }
    /**
     * @deprecated use `record` instead.
     */
    get model() {
        return this.record;
    }
    /**
     * @inheritdoc
     */
    save(token, record) {
        this._storageSet(this.storageKey, {
            token: token,
            record: record,
        });
        super.save(token, record);
    }
    /**
     * @inheritdoc
     */
    clear() {
        this._storageRemove(this.storageKey);
        super.clear();
    }
    // ---------------------------------------------------------------
    // Internal helpers:
    // ---------------------------------------------------------------
    /**
     * Retrieves `key` from the browser's local storage
     * (or runtime/memory if local storage is undefined).
     */
    _storageGet(key) {
        if (typeof window !== "undefined" && window?.localStorage) {
            const rawValue = window.localStorage.getItem(key) || "";
            try {
                return JSON.parse(rawValue);
            }
            catch (e) {
                // not a json
                return rawValue;
            }
        }
        // fallback
        return this.storageFallback[key];
    }
    /**
     * Stores a new data in the browser's local storage
     * (or runtime/memory if local storage is undefined).
     */
    _storageSet(key, value) {
        if (typeof window !== "undefined" && window?.localStorage) {
            // store in local storage
            let normalizedVal = value;
            if (typeof value !== "string") {
                normalizedVal = JSON.stringify(value);
            }
            window.localStorage.setItem(key, normalizedVal);
        }
        else {
            // store in fallback
            this.storageFallback[key] = value;
        }
    }
    /**
     * Removes `key` from the browser's local storage and the runtime/memory.
     */
    _storageRemove(key) {
        // delete from local storage
        if (typeof window !== "undefined" && window?.localStorage) {
            window.localStorage?.removeItem(key);
        }
        // delete from fallback
        delete this.storageFallback[key];
    }
    /**
     * Updates the current store state on localStorage change.
     */
    _bindStorageEvent() {
        if (typeof window === "undefined" ||
            !window?.localStorage ||
            !window.addEventListener) {
            return;
        }
        window.addEventListener("storage", (e) => {
            if (e.key != this.storageKey) {
                return;
            }
            const data = this._storageGet(this.storageKey) || {};
            super.save(data.token || "", data.record || data.model || null);
        });
    }
}

/**
 * BaseService class that should be inherited from all API services.
 */
class BaseService {
    constructor(client) {
        this.client = client;
    }
}

class SettingsService extends BaseService {
    /**
     * Fetch all available app settings.
     *
     * @throws {ClientResponseError}
     */
    getAll(options) {
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send("/api/settings", options);
    }
    /**
     * Bulk updates app settings.
     *
     * @throws {ClientResponseError}
     */
    update(bodyParams, options) {
        options = Object.assign({
            method: "PATCH",
            body: bodyParams,
        }, options);
        return this.client.send("/api/settings", options);
    }
    /**
     * Performs a S3 filesystem connection test.
     *
     * The currently supported `filesystem` are "storage" and "backups".
     *
     * @throws {ClientResponseError}
     */
    testS3(filesystem = "storage", options) {
        options = Object.assign({
            method: "POST",
            body: {
                filesystem: filesystem,
            },
        }, options);
        this.client.send("/api/settings/test/s3", options);
        return true;
    }
    /**
     * Sends a test email.
     *
     * The possible `emailTemplate` values are:
     * - verification
     * - password-reset
     * - email-change
     *
     * @throws {ClientResponseError}
     */
    testEmail(collectionIdOrName, toEmail, emailTemplate, options) {
        options = Object.assign({
            method: "POST",
            body: {
                email: toEmail,
                template: emailTemplate,
                collection: collectionIdOrName,
            },
        }, options);
        this.client.send("/api/settings/test/email", options);
        return true;
    }
    /**
     * Generates a new Apple OAuth2 client secret.
     *
     * @throws {ClientResponseError}
     */
    generateAppleClientSecret(clientId, teamId, keyId, privateKey, duration, options) {
        options = Object.assign({
            method: "POST",
            body: {
                clientId,
                teamId,
                keyId,
                privateKey,
                duration,
            },
        }, options);
        return this.client.send("/api/settings/apple/generate-client-secret", options);
    }
}

class CrudService extends BaseService {
    /**
     * Response data decoder.
     */
    decode(data) {
        return data;
    }
    getFullList(batchOrqueryParams, options) {
        if (typeof batchOrqueryParams == "number") {
            return this._getFullList(batchOrqueryParams, options);
        }
        options = Object.assign({}, batchOrqueryParams, options);
        let batch = 500;
        if (options.batch) {
            batch = options.batch;
            delete options.batch;
        }
        return this._getFullList(batch, options);
    }
    /**
     * Returns paginated items list.
     *
     * You can use the generic T to supply a wrapper type of the crud model.
     *
     * @throws {ClientResponseError}
     */
    getList(page = 1, perPage = 30, options) {
        options = Object.assign({
            method: "GET",
        }, options);
        options.query = Object.assign({
            page: page,
            perPage: perPage,
        }, options.query);
        const responseData = this.client.send(this.baseCrudPath, options);
        responseData.items =
            responseData.items?.map((item) => {
                return this.decode(item);
            }) || [];
        return responseData;
    }
    /**
     * Returns the first found item by the specified filter.
     *
     * Internally it calls `getList(1, 1, { filter, skipTotal })` and
     * returns the first found item.
     *
     * You can use the generic T to supply a wrapper type of the crud model.
     *
     * For consistency with `getOne`, this method will throw a 404
     * ClientResponseError if no item was found.
     *
     * @throws {ClientResponseError}
     */
    getFirstListItem(filter, options) {
        options = Object.assign({
            requestKey: "one_by_filter_" + this.baseCrudPath + "_" + filter,
        }, options);
        options.query = Object.assign({
            filter: filter,
            skipTotal: 1,
        }, options.query);
        const result = this.getList(1, 1, options);
        if (!result?.items?.length) {
            throw new ClientResponseError({
                status: 404,
                response: {
                    code: 404,
                    message: "The requested resource wasn't found.",
                    data: {},
                },
            });
        }
        return result.items[0];
    }
    /**
     * Returns single item by its id.
     *
     * You can use the generic T to supply a wrapper type of the crud model.
     *
     * If `id` is empty it will throw a 404 error.
     *
     * @throws {ClientResponseError}
     */
    getOne(id, options) {
        if (!id) {
            throw new ClientResponseError({
                url: this.client.buildURL(this.baseCrudPath + "/"),
                status: 404,
                response: {
                    code: 404,
                    message: "Missing required record id.",
                    data: {},
                },
            });
        }
        options = Object.assign({
            method: "GET",
        }, options);
        const responseData = this.client.send(this.baseCrudPath + "/" + encodeURIComponent(id), options);
        return this.decode(responseData);
    }
    /**
     * Creates a new item.
     *
     * You can use the generic T to supply a wrapper type of the crud model.
     *
     * @throws {ClientResponseError}
     */
    create(bodyParams, options) {
        options = Object.assign({
            method: "POST",
            body: bodyParams,
        }, options);
        const responseData = this.client.send(this.baseCrudPath, options);
        return this.decode(responseData);
    }
    /**
     * Updates an existing item by its id.
     *
     * You can use the generic T to supply a wrapper type of the crud model.
     *
     * @throws {ClientResponseError}
     */
    update(id, bodyParams, options) {
        options = Object.assign({
            method: "PATCH",
            body: bodyParams,
        }, options);
        const responseData = this.client.send(this.baseCrudPath + "/" + encodeURIComponent(id), options);
        return this.decode(responseData);
    }
    /**
     * Deletes an existing item by its id.
     *
     * @throws {ClientResponseError}
     */
    delete(id, options) {
        options = Object.assign({
            method: "DELETE",
        }, options);
        const responseData = this.client.send(this.baseCrudPath + "/" + encodeURIComponent(id), options);
        return responseData;
    }
    /**
     * Returns a promise with all list items batch fetched at once.
     */
    _getFullList(batchSize = 500, options) {
        options = options || {};
        options.query = Object.assign({
            skipTotal: 1,
        }, options.query);
        let result = [];
        let request = (page) => {
            const list = this.getList(page, batchSize || 500, options);
            const castedList = list;
            const items = castedList.items;
            result = result.concat(items);
            if (items.length == list.perPage) {
                return request(page + 1);
            }
            return result;
        };
        return request(1);
    }
}

function normalizeLegacyOptionsArgs(legacyWarn, baseOptions, bodyOrOptions, query) {
    const hasBodyOrOptions = typeof bodyOrOptions !== "undefined";
    const hasQuery = typeof query !== "undefined";
    if (!hasQuery && !hasBodyOrOptions) {
        return baseOptions;
    }
    if (hasQuery) {
        console.warn(legacyWarn);
        baseOptions.body = Object.assign({}, baseOptions.body, bodyOrOptions);
        baseOptions.query = Object.assign({}, baseOptions.query, query);
        return baseOptions;
    }
    return Object.assign(baseOptions, bodyOrOptions);
}

class RecordService extends CrudService {
    constructor(client, collectionIdOrName) {
        super(client);
        this.collectionIdOrName = collectionIdOrName;
    }
    /**
     * @inheritdoc
     */
    get baseCrudPath() {
        return this.baseCollectionPath + "/records";
    }
    /**
     * Returns the current collection service base path.
     */
    get baseCollectionPath() {
        return "/api/collections/" + encodeURIComponent(this.collectionIdOrName);
    }
    /**
     * Returns whether the current service collection is superusers.
     */
    get isSuperusers() {
        return (this.collectionIdOrName == "_superusers" ||
            this.collectionIdOrName == "_pbc_2773867675");
    }
    /**
     * @inheritdoc
     */
    getFullList(batchOrOptions, options) {
        if (typeof batchOrOptions == "number") {
            return super.getFullList(batchOrOptions, options);
        }
        const params = Object.assign({}, batchOrOptions, options);
        return super.getFullList(params);
    }
    /**
     * @inheritdoc
     */
    getList(page = 1, perPage = 30, options) {
        return super.getList(page, perPage, options);
    }
    /**
     * @inheritdoc
     */
    getFirstListItem(filter, options) {
        return super.getFirstListItem(filter, options);
    }
    /**
     * @inheritdoc
     */
    getOne(id, options) {
        return super.getOne(id, options);
    }
    /**
     * @inheritdoc
     */
    create(bodyParams, options) {
        return super.create(bodyParams, options);
    }
    /**
     * @inheritdoc
     *
     * If the current `client.authStore.record` matches with the updated id, then
     * on success the `client.authStore.record` will be updated with the new response record fields.
     */
    update(id, bodyParams, options) {
        const item = super.update(id, bodyParams, options);
        if (
        // is record auth
        this.client.authStore.record?.id === item?.id &&
            (this.client.authStore.record?.collectionId === this.collectionIdOrName ||
                this.client.authStore.record?.collectionName === this.collectionIdOrName)) {
            let authExpand = Object.assign({}, this.client.authStore.record.expand);
            let authRecord = Object.assign({}, this.client.authStore.record, item);
            if (authExpand) {
                // for now "merge" only top-level expand
                authRecord.expand = Object.assign(authExpand, item.expand);
            }
            this.client.authStore.save(this.client.authStore.token, authRecord);
        }
        return item;
    }
    /**
     * @inheritdoc
     *
     * If the current `client.authStore.record` matches with the deleted id,
     * then on success the `client.authStore` will be cleared.
     */
    delete(id, options) {
        const success = super.delete(id, options);
        if (success &&
            // is record auth
            this.client.authStore.record?.id === id &&
            (this.client.authStore.record?.collectionId === this.collectionIdOrName ||
                this.client.authStore.record?.collectionName === this.collectionIdOrName)) {
            this.client.authStore.clear();
        }
        return success;
    }
    // ---------------------------------------------------------------
    // Auth handlers
    // ---------------------------------------------------------------
    /**
     * Prepare successful collection authorization response.
     */
    authResponse(responseData) {
        const record = this.decode(responseData?.record || {});
        this.client.authStore.save(responseData?.token, record);
        return Object.assign({}, responseData, {
            // normalize common fields
            token: responseData?.token || "",
            record: record,
        });
    }
    /**
     * Returns all available collection auth methods.
     *
     * @throws {ClientResponseError}
     */
    listAuthMethods(options) {
        options = Object.assign({
            method: "GET",
            // @todo remove after deleting the pre v0.23 API response fields
            fields: "mfa,otp,password,oauth2",
        }, options);
        return this.client.send(this.baseCollectionPath + "/auth-methods", options);
    }
    /**
     * Authenticate a single auth collection record via its username/email and password.
     *
     * On success, this method also automatically updates
     * the client's AuthStore data and returns:
     * - the authentication token
     * - the authenticated record model
     *
     * @throws {ClientResponseError}
     */
    authWithPassword(usernameOrEmail, password, options) {
        options = Object.assign({
            method: "POST",
            body: {
                identity: usernameOrEmail,
                password: password,
            },
        }, options);
        let authData = this.client.send(this.baseCollectionPath + "/auth-with-password", options);
        authData = this.authResponse(authData);
        return authData;
    }
    authWithOAuth2Code(provider, code, codeVerifier, redirectURL, createData, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                provider: provider,
                code: code,
                codeVerifier: codeVerifier,
                redirectURL: redirectURL,
                createData: createData,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of authWithOAuth2Code(provider, code, codeVerifier, redirectURL, createData?, body?, query?) is deprecated. Consider replacing it with authWithOAuth2Code(provider, code, codeVerifier, redirectURL, createData?, options?).", options, bodyOrOptions, query);
        const data = this.client.send(this.baseCollectionPath + "/auth-with-oauth2", options);
        return this.authResponse(data);
    }
    authRefresh(bodyOrOptions, query) {
        let options = {
            method: "POST",
        };
        options = normalizeLegacyOptionsArgs("This form of authRefresh(body?, query?) is deprecated. Consider replacing it with authRefresh(options?).", options, bodyOrOptions, query);
        const data = this.client.send(this.baseCollectionPath + "/auth-refresh", options);
        return this.authResponse(data);
    }
    requestPasswordReset(email, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                email: email,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of requestPasswordReset(email, body?, query?) is deprecated. Consider replacing it with requestPasswordReset(email, options?).", options, bodyOrOptions, query);
        this.client.send(this.baseCollectionPath + "/request-password-reset", options);
        return true;
    }
    confirmPasswordReset(passwordResetToken, password, passwordConfirm, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                token: passwordResetToken,
                password: password,
                passwordConfirm: passwordConfirm,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of confirmPasswordReset(token, password, passwordConfirm, body?, query?) is deprecated. Consider replacing it with confirmPasswordReset(token, password, passwordConfirm, options?).", options, bodyOrOptions, query);
        this.client.send(this.baseCollectionPath + "/confirm-password-reset", options);
        return true;
    }
    requestVerification(email, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                email: email,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of requestVerification(email, body?, query?) is deprecated. Consider replacing it with requestVerification(email, options?).", options, bodyOrOptions, query);
        this.client.send(this.baseCollectionPath + "/request-verification", options);
        return true;
    }
    confirmVerification(verificationToken, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                token: verificationToken,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of confirmVerification(token, body?, query?) is deprecated. Consider replacing it with confirmVerification(token, options?).", options, bodyOrOptions, query);
        this.client.send(this.baseCollectionPath + "/confirm-verification", options);
        // on success manually update the current auth record verified state
        const payload = getTokenPayload(verificationToken);
        const model = this.client.authStore.record;
        if (model &&
            !model.verified &&
            model.id === payload.id &&
            model.collectionId === payload.collectionId) {
            model.verified = true;
            this.client.authStore.save(this.client.authStore.token, model);
        }
        return true;
    }
    requestEmailChange(newEmail, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                newEmail: newEmail,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of requestEmailChange(newEmail, body?, query?) is deprecated. Consider replacing it with requestEmailChange(newEmail, options?).", options, bodyOrOptions, query);
        this.client.send(this.baseCollectionPath + "/request-email-change", options);
        return true;
    }
    confirmEmailChange(emailChangeToken, password, bodyOrOptions, query) {
        let options = {
            method: "POST",
            body: {
                token: emailChangeToken,
                password: password,
            },
        };
        options = normalizeLegacyOptionsArgs("This form of confirmEmailChange(token, password, body?, query?) is deprecated. Consider replacing it with confirmEmailChange(token, password, options?).", options, bodyOrOptions, query);
        this.client.send(this.baseCollectionPath + "/confirm-email-change", options);
        // on success manually update the current auth record verified state
        const payload = getTokenPayload(emailChangeToken);
        const model = this.client.authStore.record;
        if (model &&
            model.id === payload.id &&
            model.collectionId === payload.collectionId) {
            this.client.authStore.clear();
        }
        return true;
    }
    /**
     * Sends auth record OTP to the provided email.
     *
     * @throws {ClientResponseError}
     */
    requestOTP(email, options) {
        options = Object.assign({
            method: "POST",
            body: { email: email },
        }, options);
        return this.client.send(this.baseCollectionPath + "/request-otp", options);
    }
    /**
     * Authenticate a single auth collection record via OTP.
     *
     * On success, this method also automatically updates
     * the client's AuthStore data and returns:
     * - the authentication token
     * - the authenticated record model
     *
     * @throws {ClientResponseError}
     */
    authWithOTP(otpId, password, options) {
        options = Object.assign({
            method: "POST",
            body: { otpId, password },
        }, options);
        const data = this.client.send(this.baseCollectionPath + "/auth-with-otp", options);
        return this.authResponse(data);
    }
    /**
     * Impersonate authenticates with the specified recordId and
     * returns a new client with the received auth token in a memory store.
     *
     * If `duration` is 0 the generated auth token will fallback
     * to the default collection auth token duration.
     *
     * This action currently requires superusers privileges.
     *
     * @throws {ClientResponseError}
     */
    impersonate(recordId, duration, options) {
        options = Object.assign({
            method: "POST",
            body: { duration: duration },
        }, options);
        options.headers = options.headers || {};
        if (!options.headers.Authorization) {
            options.headers.Authorization = this.client.authStore.token;
        }
        // create a new client loaded with the impersonated auth state
        // ---
        const client = new Client(this.client.baseURL, new BaseAuthStore(), this.client.lang);
        const authData = client.send(this.baseCollectionPath + "/impersonate/" + encodeURIComponent(recordId), options);
        client.authStore.save(authData?.token, this.decode(authData?.record || {}));
        // ---
        return client;
    }
}

class CollectionService extends CrudService {
    /**
     * @inheritdoc
     */
    get baseCrudPath() {
        return "/api/collections";
    }
    /**
     * Imports the provided collections.
     *
     * If `deleteMissing` is `true`, all local collections and their fields,
     * that are not present in the imported configuration, WILL BE DELETED
     * (including their related records data)!
     *
     * @throws {ClientResponseError}
     */
    import(collections, deleteMissing = false, options) {
        options = Object.assign({
            method: "PUT",
            body: {
                collections: collections,
                deleteMissing: deleteMissing,
            },
        }, options);
        this.client.send(this.baseCrudPath + "/import", options);
        return true;
    }
    /**
     * Returns type indexed map with scaffolded collection models
     * populated with their default field values.
     *
     * @throws {ClientResponseError}
     */
    getScaffolds(options) {
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send(this.baseCrudPath + "/meta/scaffolds", options);
    }
    /**
     * Deletes all records associated with the specified collection.
     *
     * @throws {ClientResponseError}
     */
    truncate(collectionIdOrName, options) {
        options = Object.assign({
            method: "DELETE",
        }, options);
        this.client.send(this.baseCrudPath +
            "/" +
            encodeURIComponent(collectionIdOrName) +
            "/truncate", options);
        return true;
    }
}

class LogService extends BaseService {
    /**
     * Returns paginated logs list.
     *
     * @throws {ClientResponseError}
     */
    getList(page = 1, perPage = 30, options) {
        options = Object.assign({ method: "GET" }, options);
        options.query = Object.assign({
            page: page,
            perPage: perPage,
        }, options.query);
        return this.client.send("/api/logs", options);
    }
    /**
     * Returns a single log by its id.
     *
     * If `id` is empty it will throw a 404 error.
     *
     * @throws {ClientResponseError}
     */
    getOne(id, options) {
        if (!id) {
            throw new ClientResponseError({
                url: this.client.buildURL("/api/logs/"),
                status: 404,
                response: {
                    code: 404,
                    message: "Missing required log id.",
                    data: {},
                },
            });
        }
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send("/api/logs/" + encodeURIComponent(id), options);
    }
    /**
     * Returns logs statistics.
     *
     * @throws {ClientResponseError}
     */
    getStats(options) {
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send("/api/logs/stats", options);
    }
}

class HealthService extends BaseService {
    /**
     * Checks the health status of the api.
     *
     * @throws {ClientResponseError}
     */
    check(options) {
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send("/api/health", options);
    }
}

class FileService extends BaseService {
    /**
     * @deprecated Please replace with `pb.files.getURL()`.
     */
    getUrl(record, filename, queryParams = {}) {
        console.warn("Please replace pb.files.getUrl() with pb.files.getURL()");
        return this.getURL(record, filename, queryParams);
    }
    /**
     * Builds and returns an absolute record file url for the provided filename.
     */
    getURL(record, filename, queryParams = {}) {
        if (!filename ||
            !record?.id ||
            !(record?.collectionId || record?.collectionName)) {
            return "";
        }
        const parts = [];
        parts.push("api");
        parts.push("files");
        parts.push(encodeURIComponent(record.collectionId || record.collectionName));
        parts.push(encodeURIComponent(record.id));
        parts.push(encodeURIComponent(filename));
        let result = this.client.buildURL(parts.join("/"));
        if (Object.keys(queryParams).length) {
            // normalize the download query param for consistency with the Dart sdk
            if (queryParams.download === false) {
                delete queryParams.download;
            }
            const params = new URLSearchParams(queryParams);
            result += (result.includes("?") ? "&" : "?") + params;
        }
        return result;
    }
    /**
     * Requests a new private file access token for the current auth model.
     *
     * @throws {ClientResponseError}
     */
    getToken(options) {
        options = Object.assign({
            method: "POST",
        }, options);
        const data = this.client.send("/api/files/token", options);
        return data?.token || "";
    }
}

class BackupService extends BaseService {
    /**
     * Returns list with all available backup files.
     *
     * @throws {ClientResponseError}
     */
    getFullList(options) {
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send("/api/backups", options);
    }
    /**
     * Initializes a new backup.
     *
     * @throws {ClientResponseError}
     */
    create(basename, options) {
        options = Object.assign({
            method: "POST",
            body: {
                name: basename,
            },
        }, options);
        this.client.send("/api/backups", options);
        return true;
    }
    /**
     * Uploads an existing backup file.
     *
     * Example:
     *
     * ```js
     * await pb.backups.upload({
     *     file: new Blob([...]),
     * });
     * ```
     *
     * @throws {ClientResponseError}
     */
    upload(bodyParams, options) {
        options = Object.assign({
            method: "POST",
            body: bodyParams,
        }, options);
        this.client.send("/api/backups/upload", options);
        return true;
    }
    /**
     * Deletes a single backup file.
     *
     * @throws {ClientResponseError}
     */
    delete(key, options) {
        options = Object.assign({
            method: "DELETE",
        }, options);
        this.client.send(`/api/backups/${encodeURIComponent(key)}`, options);
        return true;
    }
    /**
     * Initializes an app data restore from an existing backup.
     *
     * @throws {ClientResponseError}
     */
    restore(key, options) {
        options = Object.assign({
            method: "POST",
        }, options);
        this.client.send(`/api/backups/${encodeURIComponent(key)}/restore`, options);
        return true;
    }
    /**
     * Builds a download url for a single existing backup using a
     * superuser file token and the backup file key.
     *
     * The file token can be generated via `pb.files.getToken()`.
     */
    getDownloadURL(token, key) {
        return this.client.buildURL(`/api/backups/${encodeURIComponent(key)}?token=${encodeURIComponent(token)}`);
    }
}

class CronService extends BaseService {
    /**
     * Returns list with all registered cron jobs.
     *
     * @throws {ClientResponseError}
     */
    getFullList(options) {
        options = Object.assign({
            method: "GET",
        }, options);
        return this.client.send("/api/crons", options);
    }
    /**
     * Runs the specified cron job.
     *
     * @throws {ClientResponseError}
     */
    run(jobId, options) {
        options = Object.assign({
            method: "POST",
        }, options);
        this.client.send(`/api/crons/${encodeURIComponent(jobId)}`, options);
        return true;
    }
}

/**
 * Checks if the specified value is a file (aka. File, Blob, RN file object).
 */
function isFile(val) {
    return ((typeof Blob !== "undefined" && val instanceof Blob) ||
        (typeof File !== "undefined" && val instanceof File));
}
/**
 * Loosely checks if the specified body is a FormData instance.
 */
function isFormData(body) {
    return (body &&
        // we are checking the constructor name because FormData
        // is not available natively in some environments and the
        // polyfill(s) may not be globally accessible
        (body.constructor.name === "FormData" ||
            // fallback to global FormData instance check
            // note: this is needed because the constructor.name could be different in case of
            //       custom global FormData implementation, eg. React Native on Android/iOS
            (typeof FormData !== "undefined" && body instanceof FormData)));
}
/**
 * Checks if the submitted body object has at least one Blob/File field value.
 */
function hasFileField(body) {
    for (const key in body) {
        const values = Array.isArray(body[key]) ? body[key] : [body[key]];
        for (const v of values) {
            if (isFile(v)) {
                return true;
            }
        }
    }
    return false;
}
/**
 * Converts analyzes the provided body and converts it to FormData
 * in case a plain object with File/Blob values is used.
 */
function convertToFormDataIfNeeded(body) {
    if (typeof FormData === "undefined" ||
        typeof body === "undefined" ||
        typeof body !== "object" ||
        body === null ||
        isFormData(body) ||
        !hasFileField(body)) {
        return body;
    }
    const form = new FormData();
    for (const key in body) {
        const val = body[key];
        if (typeof val === "object" && !hasFileField({ data: val })) {
            // send json-like values as jsonPayload to avoid the implicit string value normalization
            let payload = {};
            payload[key] = val;
            form.append("@jsonPayload", JSON.stringify(payload));
        }
        else {
            // in case of mixed string and file/blob
            const normalizedVal = Array.isArray(val) ? val : [val];
            for (let v of normalizedVal) {
                form.append(key, v);
            }
        }
    }
    return form;
}
/**
 * Converts the provided FormData instance into a plain object.
 *
 * For consistency with the server multipart/form-data inferring,
 * the following normalization rules are applied for plain multipart string values:
 *   - "true" is converted to the json "true"
 *   - "false" is converted to the json "false"
 *   - numeric strings are converted to json number ONLY if the resulted
 *     minimal number string representation is the same as the provided raw string
 *     (aka. scientific notations, "Infinity", "0.0", "0001", etc. are kept as string)
 *   - any other string (empty string too) is left as it is
 */
function convertFormDataToObject(formData) {
    let result = {};
    formData.forEach((v, k) => {
        if (k === "@jsonPayload" && typeof v == "string") {
            try {
                let parsed = JSON.parse(v);
                Object.assign(result, parsed);
            }
            catch (err) {
                console.warn("@jsonPayload error:", err);
            }
        }
        else {
            if (typeof result[k] !== "undefined") {
                if (!Array.isArray(result[k])) {
                    result[k] = [result[k]];
                }
                result[k].push(inferFormDataValue(v));
            }
            else {
                result[k] = inferFormDataValue(v);
            }
        }
    });
    return result;
}
const inferNumberCharsRegex = /^[\-\.\d]+$/;
function inferFormDataValue(value) {
    if (typeof value != "string") {
        return value;
    }
    if (value == "true") {
        return true;
    }
    if (value == "false") {
        return false;
    }
    // note: expects the provided raw string to match exactly with the minimal string representation of the parsed number
    if ((value[0] === "-" || (value[0] >= "0" && value[0] <= "9")) &&
        inferNumberCharsRegex.test(value)) {
        let num = +value;
        if ("" + num === value) {
            return num;
        }
    }
    return value;
}

// -------------------------------------------------------------------
// list of known SendOptions keys (everything else is treated as query param)
const knownSendOptionsKeys = [
    "fetch",
    "headers",
    "body",
    "query",
    "params",
    // ---,
    "cache",
    "credentials",
    "headers",
    "integrity",
    "keepalive",
    "method",
    "mode",
    "redirect",
    "referrer",
    "referrerPolicy",
    "signal",
    "window",
];
// modifies in place the provided options by moving unknown send options as query parameters.
function normalizeUnknownQueryParams(options) {
    if (!options) {
        return;
    }
    options.query = options.query || {};
    for (let key in options) {
        if (knownSendOptionsKeys.includes(key)) {
            continue;
        }
        options.query[key] = options[key];
        delete options[key];
    }
}
function serializeQueryParams(params) {
    const result = [];
    for (const key in params) {
        if (params[key] === null || typeof params[key] === "undefined") {
            // skip null or undefined query params
            continue;
        }
        const value = params[key];
        const encodedKey = encodeURIComponent(key);
        if (Array.isArray(value)) {
            // repeat array params
            for (const v of value) {
                result.push(encodedKey + "=" + encodeURIComponent(v));
            }
        }
        else if (value instanceof Date) {
            result.push(encodedKey + "=" + encodeURIComponent(value.toISOString()));
        }
        else if (typeof value !== null && typeof value === "object") {
            result.push(encodedKey + "=" + encodeURIComponent(JSON.stringify(value)));
        }
        else {
            result.push(encodedKey + "=" + encodeURIComponent(value));
        }
    }
    return result.join("&");
}

class BatchService extends BaseService {
    constructor() {
        super(...arguments);
        this.requests = [];
        this.subs = {};
    }
    /**
     * Starts constructing a batch request entry for the specified collection.
     */
    collection(collectionIdOrName) {
        if (!this.subs[collectionIdOrName]) {
            this.subs[collectionIdOrName] = new SubBatchService(this.requests, collectionIdOrName);
        }
        return this.subs[collectionIdOrName];
    }
    /**
     * Sends the batch requests.
     *
     * @throws {ClientResponseError}
     */
    send(options) {
        const formData = new FormData();
        const jsonData = [];
        for (let i = 0; i < this.requests.length; i++) {
            const req = this.requests[i];
            jsonData.push({
                method: req.method,
                url: req.url,
                headers: req.headers,
                body: req.json,
            });
            if (req.files) {
                for (let key in req.files) {
                    const files = req.files[key] || [];
                    for (let file of files) {
                        formData.append("requests." + i + "." + key, file);
                    }
                }
            }
        }
        formData.append("@jsonPayload", JSON.stringify({ requests: jsonData }));
        options = Object.assign({
            method: "POST",
            body: formData,
        }, options);
        return this.client.send("/api/batch", options);
    }
}
class SubBatchService {
    constructor(requests, collectionIdOrName) {
        this.requests = [];
        this.requests = requests;
        this.collectionIdOrName = collectionIdOrName;
    }
    /**
     * Registers a record upsert request into the current batch queue.
     *
     * The request will be executed as update if `bodyParams` have a valid existing record `id` value, otherwise - create.
     */
    upsert(bodyParams, options) {
        options = Object.assign({
            body: bodyParams || {},
        }, options);
        const request = {
            method: "PUT",
            url: "/api/collections/" +
                encodeURIComponent(this.collectionIdOrName) +
                "/records",
        };
        this.prepareRequest(request, options);
        this.requests.push(request);
    }
    /**
     * Registers a record create request into the current batch queue.
     */
    create(bodyParams, options) {
        options = Object.assign({
            body: bodyParams || {},
        }, options);
        const request = {
            method: "POST",
            url: "/api/collections/" +
                encodeURIComponent(this.collectionIdOrName) +
                "/records",
        };
        this.prepareRequest(request, options);
        this.requests.push(request);
    }
    /**
     * Registers a record update request into the current batch queue.
     */
    update(id, bodyParams, options) {
        options = Object.assign({
            body: bodyParams || {},
        }, options);
        const request = {
            method: "PATCH",
            url: "/api/collections/" +
                encodeURIComponent(this.collectionIdOrName) +
                "/records/" +
                encodeURIComponent(id),
        };
        this.prepareRequest(request, options);
        this.requests.push(request);
    }
    /**
     * Registers a record delete request into the current batch queue.
     */
    delete(id, options) {
        options = Object.assign({}, options);
        const request = {
            method: "DELETE",
            url: "/api/collections/" +
                encodeURIComponent(this.collectionIdOrName) +
                "/records/" +
                encodeURIComponent(id),
        };
        this.prepareRequest(request, options);
        this.requests.push(request);
    }
    prepareRequest(request, options) {
        normalizeUnknownQueryParams(options);
        request.headers = options.headers;
        request.json = {};
        request.files = {};
        // serialize query parameters
        // -----------------------------------------------------------
        if (typeof options.query !== "undefined") {
            const query = serializeQueryParams(options.query);
            if (query) {
                request.url += (request.url.includes("?") ? "&" : "?") + query;
            }
        }
        // extract json and files body data
        // -----------------------------------------------------------
        let body = options.body;
        if (isFormData(body)) {
            body = convertFormDataToObject(body);
        }
        for (const key in body) {
            const val = body[key];
            if (isFile(val)) {
                request.files[key] = request.files[key] || [];
                request.files[key].push(val);
            }
            else if (Array.isArray(val)) {
                const foundFiles = [];
                const foundRegular = [];
                for (const v of val) {
                    if (isFile(v)) {
                        foundFiles.push(v);
                    }
                    else {
                        foundRegular.push(v);
                    }
                }
                if (foundFiles.length > 0 && foundFiles.length == val.length) {
                    // only files
                    // ---
                    request.files[key] = request.files[key] || [];
                    for (let file of foundFiles) {
                        request.files[key].push(file);
                    }
                }
                else {
                    // empty or mixed array (both regular and File/Blob values)
                    // ---
                    request.json[key] = foundRegular;
                    if (foundFiles.length > 0) {
                        // add "+" to append if not already since otherwise
                        // the existing regular files will be deleted
                        // (the mixed values order is preserved only within their corresponding groups)
                        let fileKey = key;
                        if (!key.startsWith("+") && !key.endsWith("+")) {
                            fileKey += "+";
                        }
                        request.files[fileKey] = request.files[fileKey] || [];
                        for (let file of foundFiles) {
                            request.files[fileKey].push(file);
                        }
                    }
                }
            }
            else {
                request.json[key] = val;
            }
        }
    }
}

/**
 * PocketBase JS Client.
 */
class Client {
    /**
     * Legacy getter alias for baseURL.
     * @deprecated Please replace with baseURL.
     */
    get baseUrl() {
        return this.baseURL;
    }
    /**
     * Legacy setter alias for baseURL.
     * @deprecated Please replace with baseURL.
     */
    set baseUrl(v) {
        this.baseURL = v;
    }
    constructor(baseURL = "/", authStore, lang = "en-US") {
        this.recordServices = {};
        this.baseURL = baseURL;
        this.lang = lang;
        if (authStore) {
            this.authStore = authStore;
        }
        else if (typeof window != "undefined" && !!window.Deno) {
            // note: to avoid common security issues we fallback to runtime/memory store in case the code is running in Deno env
            this.authStore = new BaseAuthStore();
        }
        else {
            this.authStore = new LocalAuthStore();
        }
        // common services
        this.collections = new CollectionService(this);
        this.files = new FileService(this);
        this.logs = new LogService(this);
        this.settings = new SettingsService(this);
        this.health = new HealthService(this);
        this.backups = new BackupService(this);
        this.crons = new CronService(this);
    }
    /**
     * @deprecated
     * With PocketBase v0.23.0 admins are converted to a regular auth
     * collection named "_superusers", aka. you can use directly collection("_superusers").
     */
    get admins() {
        return this.collection("_superusers");
    }
    /**
     * Creates a new batch handler for sending multiple transactional
     * create/update/upsert/delete collection requests in one network call.
     *
     * Example:
     * ```js
     * const batch = pb.createBatch();
     *
     * batch.collection("example1").create({ ... })
     * batch.collection("example2").update("RECORD_ID", { ... })
     * batch.collection("example3").delete("RECORD_ID")
     * batch.collection("example4").upsert({ ... })
     *
     * await batch.send()
     * ```
     */
    createBatch() {
        return new BatchService(this);
    }
    /**
     * Returns the RecordService associated to the specified collection.
     */
    collection(idOrName) {
        if (!this.recordServices[idOrName]) {
            this.recordServices[idOrName] = new RecordService(this, idOrName);
        }
        return this.recordServices[idOrName];
    }
    /**
     * Constructs a filter expression with placeholders populated from a parameters object.
     *
     * Placeholder parameters are defined with the `{:paramName}` notation.
     *
     * The following parameter values are supported:
     *
     * - `string` (_single quotes are autoescaped_)
     * - `number`
     * - `boolean`
     * - `Date` object (_stringified into the PocketBase datetime format_)
     * - `null`
     * - everything else is converted to a string using `JSON.stringify()`
     *
     * Example:
     *
     * ```js
     * pb.collection("example").getFirstListItem(pb.filter(
     *    'title ~ {:title} && created >= {:created}',
     *    { title: "example", created: new Date()}
     * ))
     * ```
     */
    filter(raw, params) {
        if (!params) {
            return raw;
        }
        for (let key in params) {
            let val = params[key];
            switch (typeof val) {
                case "boolean":
                case "number":
                    val = "" + val;
                    break;
                case "string":
                    val = "'" + val.replace(/'/g, "\\'") + "'";
                    break;
                default:
                    if (val === null) {
                        val = "null";
                    }
                    else if (val instanceof Date) {
                        val = "'" + val.toISOString().replace("T", " ") + "'";
                    }
                    else {
                        val = "'" + JSON.stringify(val).replace(/'/g, "\\'") + "'";
                    }
            }
            raw = raw.replaceAll("{:" + key + "}", val);
        }
        return raw;
    }
    /**
     * @deprecated Please use `pb.files.getURL()`.
     */
    getFileUrl(record, filename, queryParams = {}) {
        console.warn("Please replace pb.getFileUrl() with pb.files.getURL()");
        return this.files.getURL(record, filename, queryParams);
    }
    /**
     * @deprecated Please use `pb.buildURL()`.
     */
    buildUrl(path) {
        console.warn("Please replace pb.buildUrl() with pb.buildURL()");
        return this.buildURL(path);
    }
    /**
     * Builds a full client url by safely concatenating the provided path.
     */
    buildURL(path) {
        let url = this.baseURL;
        // construct an absolute base url if in a browser environment
        if (typeof window !== "undefined" &&
            !!window.location &&
            !url.startsWith("https://") &&
            !url.startsWith("http://")) {
            url = window.location.origin?.endsWith("/")
                ? window.location.origin.substring(0, window.location.origin.length - 1)
                : window.location.origin || "";
            if (!this.baseURL.startsWith("/")) {
                url += window.location.pathname || "/";
                url += url.endsWith("/") ? "" : "/";
            }
            url += this.baseURL;
        }
        // concatenate the path
        if (path) {
            url += url.endsWith("/") ? "" : "/"; // append trailing slash if missing
            url += path.startsWith("/") ? path.substring(1) : path;
        }
        return url;
    }
    /**
     * Sends an api http request.
     *
     * @throws {ClientResponseError}
     */
    send(path, options) {
        options = this.initSendOptions(path, options);
        // build url + path
        let url = this.buildURL(path);
        if (this.beforeSend) {
            const result = Object.assign({}, this.beforeSend(url, options));
            if (typeof result.url !== "undefined" ||
                typeof result.options !== "undefined") {
                url = result.url || url;
                options = result.options || options;
            }
            else if (Object.keys(result).length) {
                // legacy behavior
                options = result;
                console?.warn &&
                    console.warn("Deprecated format of beforeSend return: please use `return { url, options }`, instead of `return options`.");
            }
        }
        // serialize the query parameters
        if (typeof options.query !== "undefined") {
            const query = serializeQueryParams(options.query);
            if (query) {
                url += (url.includes("?") ? "&" : "?") + query;
            }
            delete options.query;
        }
        // ensures that the json body is serialized
        if (this.getHeader(options.headers, "Content-Type") == "application/json" &&
            options.body &&
            typeof options.body !== "string") {
            options.body = JSON.stringify(options.body);
        }
        const fetchFunc = options.fetch || $http.send;
        // send the request
        try {
            console.log(`fetching ${url} with method ${options.method}`);
            const response = fetchFunc({
                url: url,
                // method: options.method,
                // headers: options.headers,
                // body: options.body,
            });
            let data = {};
            try {
                data = response.json();
            }
            catch (_) {
                // all api responses are expected to return json
                // with the exception of the realtime event and 204
            }
            if (this.afterSend) {
                data = this.afterSend(response, data, options);
            }
            if (response.statusCode >= 400) {
                throw new ClientResponseError({
                    url,
                    status: response.statusCode,
                    data: data,
                });
            }
            return data;
        }
        catch (err) {
            throw new ClientResponseError(err);
        }
    }
    /**
     * Shallow copy the provided object and takes care to initialize
     * any options required to preserve the backward compatability.
     *
     * @param  {SendOptions} options
     * @return {SendOptions}
     */
    // @ts-ignore
    initSendOptions(path, options) {
        options = Object.assign({ method: "GET" }, options);
        // auto convert the body to FormData, if needed
        options.body = convertToFormDataIfNeeded(options.body);
        // move unknown send options as query parameters
        normalizeUnknownQueryParams(options);
        // add the json header, if not explicitly set
        // (for FormData body the Content-Type header should be skipped since the boundary is autogenerated)
        if (this.getHeader(options.headers, "Content-Type") === null &&
            !isFormData(options.body)) {
            options.headers = Object.assign({}, options.headers, {
                "Content-Type": "application/json",
            });
        }
        // add Accept-Language header, if not explicitly set
        if (this.getHeader(options.headers, "Accept-Language") === null) {
            options.headers = Object.assign({}, options.headers, {
                "Accept-Language": this.lang,
            });
        }
        // check if Authorization header can be added
        if (
        // has valid token
        this.authStore.token &&
            // auth header is not explicitly set
            this.getHeader(options.headers, "Authorization") === null) {
            options.headers = Object.assign({}, options.headers, {
                Authorization: this.authStore.token,
            });
        }
        return options;
    }
    /**
     * Extracts the header with the provided name in case-insensitive manner.
     * Returns `null` if no header matching the name is found.
     */
    getHeader(headers, name) {
        headers = headers || {};
        name = name.toLowerCase();
        for (let key in headers) {
            if (key.toLowerCase() == name) {
                return headers[key];
            }
        }
        return null;
    }
}

export { BaseAuthStore, BatchService, ClientResponseError, CollectionService, CrudService, HealthService, LocalAuthStore, LogService, RecordService, SubBatchService, cookieParse, cookieSerialize, Client as default, getTokenPayload, isTokenExpired, normalizeUnknownQueryParams, serializeQueryParams };
