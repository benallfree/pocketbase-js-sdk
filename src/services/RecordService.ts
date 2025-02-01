import Client from "@/Client";
import { BaseAuthStore } from "@/stores/BaseAuthStore";
import { CrudService } from "@/services/CrudService";
import { ListResult, RecordModel } from "@/tools/dtos";
import { normalizeLegacyOptionsArgs } from "@/tools/legacy";
import {
    CommonOptions,
    RecordFullListOptions,
    RecordListOptions,
    RecordOptions,
} from "@/tools/options";
import { getTokenPayload } from "@/tools/jwt";

export interface RecordAuthResponse<T = RecordModel> {
    /**
     * The signed PocketBase auth record.
     */
    record: T;

    /**
     * The PocketBase record auth token.
     *
     * If you are looking for the OAuth2 access and refresh tokens
     * they are available under the `meta.accessToken` and `meta.refreshToken` props.
     */
    token: string;

    /**
     * Auth meta data usually filled when OAuth2 is used.
     */
    meta?: { [key: string]: any };
}

export interface AuthProviderInfo {
    name: string;
    displayName: string;
    state: string;
    authURL: string;
    codeVerifier: string;
    codeChallenge: string;
    codeChallengeMethod: string;
}

export interface AuthMethodsList {
    mfa: {
        enabled: boolean;
        duration: number;
    };
    otp: {
        enabled: boolean;
        duration: number;
    };
    password: {
        enabled: boolean;
        identityFields: Array<string>;
    };
    oauth2: {
        enabled: boolean;
        providers: Array<AuthProviderInfo>;
    };
}

export interface RecordSubscription<T = RecordModel> {
    action: string; // eg. create, update, delete
    record: T;
}

export interface OTPResponse {
    otpId: string;
}

export class RecordService<M = RecordModel> extends CrudService<M> {
    readonly collectionIdOrName: string;

    constructor(client: Client, collectionIdOrName: string) {
        super(client);

        this.collectionIdOrName = collectionIdOrName;
    }

    /**
     * @inheritdoc
     */
    get baseCrudPath(): string {
        return this.baseCollectionPath + "/records";
    }

    /**
     * Returns the current collection service base path.
     */
    get baseCollectionPath(): string {
        return "/api/collections/" + encodeURIComponent(this.collectionIdOrName);
    }

    /**
     * Returns whether the current service collection is superusers.
     */
    get isSuperusers(): boolean {
        return (
            this.collectionIdOrName == "_superusers" ||
            this.collectionIdOrName == "_pbc_2773867675"
        );
    }

    // ---------------------------------------------------------------
    // Crud handlers
    // ---------------------------------------------------------------
    /**
     * @inheritdoc
     */
    getFullList<T = M>(options?: RecordFullListOptions): Array<T>;

    /**
     * @inheritdoc
     */
    getFullList<T = M>(batch?: number, options?: RecordListOptions): Array<T>;

    /**
     * @inheritdoc
     */
    getFullList<T = M>(
        batchOrOptions?: number | RecordFullListOptions,
        options?: RecordListOptions,
    ): Array<T> {
        if (typeof batchOrOptions == "number") {
            return super.getFullList<T>(batchOrOptions, options);
        }

        const params = Object.assign({}, batchOrOptions, options);

        return super.getFullList<T>(params);
    }

    /**
     * @inheritdoc
     */
    getList<T = M>(page = 1, perPage = 30, options?: RecordListOptions): ListResult<T> {
        return super.getList<T>(page, perPage, options);
    }

    /**
     * @inheritdoc
     */
    getFirstListItem<T = M>(filter: string, options?: RecordListOptions): T {
        return super.getFirstListItem<T>(filter, options);
    }

    /**
     * @inheritdoc
     */
    getOne<T = M>(id: string, options?: RecordOptions): T {
        return super.getOne<T>(id, options);
    }

    /**
     * @inheritdoc
     */
    create<T = M>(
        bodyParams?: { [key: string]: any } | FormData,
        options?: RecordOptions,
    ): T {
        return super.create<T>(bodyParams, options);
    }

    /**
     * @inheritdoc
     *
     * If the current `client.authStore.record` matches with the updated id, then
     * on success the `client.authStore.record` will be updated with the new response record fields.
     */
    update<T = M>(
        id: string,
        bodyParams?: { [key: string]: any } | FormData,
        options?: RecordOptions,
    ): T {
        const item = super.update<RecordModel>(id, bodyParams, options);
        if (
            // is record auth
            this.client.authStore.record?.id === item?.id &&
            (this.client.authStore.record?.collectionId === this.collectionIdOrName ||
                this.client.authStore.record?.collectionName === this.collectionIdOrName)
        ) {
            let authExpand = Object.assign({}, this.client.authStore.record.expand);
            let authRecord = Object.assign({}, this.client.authStore.record, item);
            if (authExpand) {
                // for now "merge" only top-level expand
                authRecord.expand = Object.assign(authExpand, item.expand);
            }

            this.client.authStore.save(this.client.authStore.token, authRecord);
        }

        return item as any as T;
    }

    /**
     * @inheritdoc
     *
     * If the current `client.authStore.record` matches with the deleted id,
     * then on success the `client.authStore` will be cleared.
     */
    delete(id: string, options?: CommonOptions): boolean {
        const success = super.delete(id, options);
        if (
            success &&
            // is record auth
            this.client.authStore.record?.id === id &&
            (this.client.authStore.record?.collectionId === this.collectionIdOrName ||
                this.client.authStore.record?.collectionName === this.collectionIdOrName)
        ) {
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
    protected authResponse<T = M>(responseData: any): RecordAuthResponse<T> {
        const record = this.decode(responseData?.record || {});

        this.client.authStore.save(responseData?.token, record as any);

        return Object.assign({}, responseData, {
            // normalize common fields
            token: responseData?.token || "",
            record: record as any as T,
        });
    }

    /**
     * Returns all available collection auth methods.
     *
     * @throws {ClientResponseError}
     */
    listAuthMethods(options?: CommonOptions): AuthMethodsList {
        options = Object.assign(
            {
                method: "GET",
                // @todo remove after deleting the pre v0.23 API response fields
                fields: "mfa,otp,password,oauth2",
            },
            options,
        );

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
    authWithPassword<T = M>(
        usernameOrEmail: string,
        password: string,
        options?: RecordOptions,
    ): RecordAuthResponse<T> {
        options = Object.assign(
            {
                method: "POST",
                body: {
                    identity: usernameOrEmail,
                    password: password,
                },
            },
            options,
        );

        let authData = this.client.send(
            this.baseCollectionPath + "/auth-with-password",
            options,
        );

        authData = this.authResponse<T>(authData);

        return authData;
    }

    /**
     * Authenticate a single auth collection record with OAuth2 code.
     *
     * If you don't have an OAuth2 code you may also want to check `authWithOAuth2` method.
     *
     * On success, this method also automatically updates
     * the client's AuthStore data and returns:
     * - the authentication token
     * - the authenticated record model
     * - the OAuth2 account data (eg. name, email, avatar, etc.)
     *
     * @throws {ClientResponseError}
     */
    authWithOAuth2Code<T = M>(
        provider: string,
        code: string,
        codeVerifier: string,
        redirectURL: string,
        createData?: { [key: string]: any },
        options?: RecordOptions,
    ): RecordAuthResponse<T>;

    authWithOAuth2Code<T = M>(
        provider: string,
        code: string,
        codeVerifier: string,
        redirectURL: string,
        createData?: { [key: string]: any },
        bodyOrOptions?: any,
        query?: any,
    ): RecordAuthResponse<T> {
        let options: any = {
            method: "POST",
            body: {
                provider: provider,
                code: code,
                codeVerifier: codeVerifier,
                redirectURL: redirectURL,
                createData: createData,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of authWithOAuth2Code(provider, code, codeVerifier, redirectURL, createData?, body?, query?) is deprecated. Consider replacing it with authWithOAuth2Code(provider, code, codeVerifier, redirectURL, createData?, options?).",
            options,
            bodyOrOptions,
            query,
        );

        const data = this.client.send(
            this.baseCollectionPath + "/auth-with-oauth2",
            options,
        );
        return this.authResponse<T>(data);
    }

    /**
     * Refreshes the current authenticated record instance and
     * returns a new token and record data.
     *
     * On success this method also automatically updates the client's AuthStore.
     *
     * @throws {ClientResponseError}
     */
    authRefresh<T = M>(options?: RecordOptions): RecordAuthResponse<T>;

    authRefresh<T = M>(bodyOrOptions?: any, query?: any): RecordAuthResponse<T> {
        let options: any = {
            method: "POST",
        };

        options = normalizeLegacyOptionsArgs(
            "This form of authRefresh(body?, query?) is deprecated. Consider replacing it with authRefresh(options?).",
            options,
            bodyOrOptions,
            query,
        );

        const data = this.client.send(this.baseCollectionPath + "/auth-refresh", options);
        return this.authResponse<T>(data);
    }

    /**
     * Sends auth record password reset request.
     *
     * @throws {ClientResponseError}
     */
    requestPasswordReset(email: string, options?: CommonOptions): boolean;

    requestPasswordReset(email: string, bodyOrOptions?: any, query?: any): boolean {
        let options: any = {
            method: "POST",
            body: {
                email: email,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of requestPasswordReset(email, body?, query?) is deprecated. Consider replacing it with requestPasswordReset(email, options?).",
            options,
            bodyOrOptions,
            query,
        );

        this.client.send(this.baseCollectionPath + "/request-password-reset", options);
        return true;
    }

    /**
     * Confirms auth record password reset request.
     *
     * @throws {ClientResponseError}
     */
    confirmPasswordReset(
        passwordResetToken: string,
        password: string,
        passwordConfirm: string,
        options?: CommonOptions,
    ): boolean;

    confirmPasswordReset(
        passwordResetToken: string,
        password: string,
        passwordConfirm: string,
        bodyOrOptions?: any,
        query?: any,
    ): boolean {
        let options: any = {
            method: "POST",
            body: {
                token: passwordResetToken,
                password: password,
                passwordConfirm: passwordConfirm,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of confirmPasswordReset(token, password, passwordConfirm, body?, query?) is deprecated. Consider replacing it with confirmPasswordReset(token, password, passwordConfirm, options?).",
            options,
            bodyOrOptions,
            query,
        );

        this.client.send(this.baseCollectionPath + "/confirm-password-reset", options);
        return true;
    }

    /**
     * Sends auth record verification email request.
     *
     * @throws {ClientResponseError}
     */
    requestVerification(email: string, options?: CommonOptions): boolean;

    requestVerification(email: string, bodyOrOptions?: any, query?: any): boolean {
        let options: any = {
            method: "POST",
            body: {
                email: email,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of requestVerification(email, body?, query?) is deprecated. Consider replacing it with requestVerification(email, options?).",
            options,
            bodyOrOptions,
            query,
        );

        this.client.send(this.baseCollectionPath + "/request-verification", options);
        return true;
    }

    /**
     * Confirms auth record email verification request.
     *
     * If the current `client.authStore.record` matches with the auth record from the token,
     * then on success the `client.authStore.record.verified` will be updated to `true`.
     *
     * @throws {ClientResponseError}
     */
    confirmVerification(verificationToken: string, options?: CommonOptions): boolean;

    confirmVerification(
        verificationToken: string,
        bodyOrOptions?: any,
        query?: any,
    ): boolean {
        let options: any = {
            method: "POST",
            body: {
                token: verificationToken,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of confirmVerification(token, body?, query?) is deprecated. Consider replacing it with confirmVerification(token, options?).",
            options,
            bodyOrOptions,
            query,
        );

        this.client.send(this.baseCollectionPath + "/confirm-verification", options);
        // on success manually update the current auth record verified state
        const payload = getTokenPayload(verificationToken);
        const model = this.client.authStore.record;
        if (
            model &&
            !model.verified &&
            model.id === payload.id &&
            model.collectionId === payload.collectionId
        ) {
            model.verified = true;
            this.client.authStore.save(this.client.authStore.token, model);
        }

        return true;
    }

    /**
     * Sends an email change request to the authenticated record model.
     *
     * @throws {ClientResponseError}
     */
    requestEmailChange(newEmail: string, options?: CommonOptions): boolean;

    requestEmailChange(newEmail: string, bodyOrOptions?: any, query?: any): boolean {
        let options: any = {
            method: "POST",
            body: {
                newEmail: newEmail,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of requestEmailChange(newEmail, body?, query?) is deprecated. Consider replacing it with requestEmailChange(newEmail, options?).",
            options,
            bodyOrOptions,
            query,
        );

        this.client.send(this.baseCollectionPath + "/request-email-change", options);
        return true;
    }

    /**
     * Confirms auth record's new email address.
     *
     * If the current `client.authStore.record` matches with the auth record from the token,
     * then on success the `client.authStore` will be cleared.
     *
     * @throws {ClientResponseError}
     */
    confirmEmailChange(
        emailChangeToken: string,
        password: string,
        options?: CommonOptions,
    ): boolean;

    confirmEmailChange(
        emailChangeToken: string,
        password: string,
        bodyOrOptions?: any,
        query?: any,
    ): boolean {
        let options: any = {
            method: "POST",
            body: {
                token: emailChangeToken,
                password: password,
            },
        };

        options = normalizeLegacyOptionsArgs(
            "This form of confirmEmailChange(token, password, body?, query?) is deprecated. Consider replacing it with confirmEmailChange(token, password, options?).",
            options,
            bodyOrOptions,
            query,
        );

        this.client.send(this.baseCollectionPath + "/confirm-email-change", options);
        // on success manually update the current auth record verified state
        const payload = getTokenPayload(emailChangeToken);
        const model = this.client.authStore.record;
        if (
            model &&
            model.id === payload.id &&
            model.collectionId === payload.collectionId
        ) {
            this.client.authStore.clear();
        }

        return true;
    }

    /**
     * Sends auth record OTP to the provided email.
     *
     * @throws {ClientResponseError}
     */
    requestOTP(email: string, options?: CommonOptions): OTPResponse {
        options = Object.assign(
            {
                method: "POST",
                body: { email: email },
            },
            options,
        );

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
    authWithOTP<T = M>(
        otpId: string,
        password: string,
        options?: CommonOptions,
    ): RecordAuthResponse<T> {
        options = Object.assign(
            {
                method: "POST",
                body: { otpId, password },
            },
            options,
        );

        const data = this.client.send(
            this.baseCollectionPath + "/auth-with-otp",
            options,
        );
        return this.authResponse<T>(data);
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
    impersonate(recordId: string, duration: number, options?: CommonOptions): Client {
        options = Object.assign(
            {
                method: "POST",
                body: { duration: duration },
            },
            options,
        );
        options.headers = options.headers || {};
        if (!options.headers.Authorization) {
            options.headers.Authorization = this.client.authStore.token;
        }

        // create a new client loaded with the impersonated auth state
        // ---
        const client = new Client(
            this.client.baseURL,
            new BaseAuthStore(),
            this.client.lang,
        );

        const authData = client.send(
            this.baseCollectionPath + "/impersonate/" + encodeURIComponent(recordId),
            options,
        );

        client.authStore.save(authData?.token, this.decode(authData?.record || {}));
        // ---

        return client;
    }
}
