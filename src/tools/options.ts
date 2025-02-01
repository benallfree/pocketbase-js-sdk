export type FetchFunction = (url: string | URL, config?: RequestInit) => Response;

export interface SendOptions extends RequestInit {
    // for backward compatibility and to minimize the verbosity,
    // any top-level field that doesn't exist in RequestInit or the
    // fields below will be treated as query parameter.
    [key: string]: any;

    /**
     * Optional custom fetch function to use for sending the request.
     */
    fetch?: typeof $http.send;

    /**
     * Custom headers to send with the requests.
     */
    headers?: { [key: string]: string };

    /**
     * The body of the request (serialized automatically for json requests).
     */
    body?: any;

    /**
     * Query parameters that will be appended to the request url.
     */
    query?: { [key: string]: any };
}

export interface CommonOptions extends SendOptions {
    fields?: string;
}

export interface ListOptions extends CommonOptions {
    page?: number;
    perPage?: number;
    sort?: string;
    filter?: string;
    skipTotal?: boolean;
}

export interface FullListOptions extends ListOptions {
    batch?: number;
}

export interface RecordOptions extends CommonOptions {
    expand?: string;
}

export interface RecordListOptions extends ListOptions, RecordOptions {}

export interface RecordFullListOptions extends FullListOptions, RecordOptions {}

export interface RecordSubscribeOptions extends SendOptions {
    fields?: string;
    filter?: string;
    expand?: string;
}

export interface LogStatsOptions extends CommonOptions {
    filter?: string;
}

export interface FileOptions extends CommonOptions {
    thumb?: string;
    download?: boolean;
}

export interface AuthOptions extends CommonOptions {
    /**
     * If autoRefreshThreshold is set it will take care to auto refresh
     * when necessary the auth data before each request to ensure that
     * the auth state is always valid.
     *
     * The value must be in seconds, aka. the amount of seconds
     * that will be subtracted from the current token `exp` claim in order
     * to determine whether it is going to expire within the specified time threshold.
     *
     * For example, if you want to auto refresh the token if it is
     * going to expire in the next 30mins (or already has expired),
     * it can be set to `1800`
     */
    autoRefreshThreshold?: number;
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
export function normalizeUnknownQueryParams(options?: SendOptions): void {
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

export function serializeQueryParams(params: { [key: string]: any }): string {
    const result: Array<string> = [];

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
        } else if (value instanceof Date) {
            result.push(encodedKey + "=" + encodeURIComponent(value.toISOString()));
        } else if (typeof value !== null && typeof value === "object") {
            result.push(encodedKey + "=" + encodeURIComponent(JSON.stringify(value)));
        } else {
            result.push(encodedKey + "=" + encodeURIComponent(value));
        }
    }

    return result.join("&");
}
