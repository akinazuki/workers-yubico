import { Response, ResponseStatus } from "./Response";
import { HmacSHA1, enc } from 'crypto-js';

// Default API servers provided from Yubico
const API_SERVERS = ["api.yubico.com", "api2.yubico.com", "api3.yubico.com", "api4.yubico.com", "api5.yubico.com"];

export type SL = number | "fast" | "secure";

export interface IYubicoConstructor {
    clientId?: string;
    secret?: string;
    sl?: SL;
    timeout?: number;
    apiServers?: string[];
}

/**
 * The class that manages the Yubico requests and stores data about the
 * client such as its ID and secret
 */
export class Yubico {
    /**
     * The client ID obtained from Yubico
     */
    private clientId: string;

    /**
     * The secret obtained from Yubico
     */
    private secret: string;

    /**
     * The sync setting for the server to use.
     * From the Yubico Docs:
     *
     * A value 0 to 100 indicating percentage of syncing required by client,
     * or strings "fast" or "secure" to use server-configured values;
     * if absent, let the server decide
     *
     */
    private sl?: SL;

    /**
     * The timeout to wait for sync responses. Without this parameter, the
     * Yubico server will automatically decide
     */
    private timeout?: number;

    /**
     * The api servers to use for the request. This is only to be used if you are running
     * your own implementation of the Yubico verification servers. Otherwise, you should
     * leave this parameter blank and it will default to Yubico's.
     */
    private apiServers?: string[];

    constructor(options?: IYubicoConstructor) {
        // Pull options from the constructor or from environment variables
        if (options && options.clientId) {
            this.clientId = options.clientId;
        } else {
            throw new Error("Either clientId must be set in the constructor");
        }

        if (options && options.secret) {
            this.secret = options.secret;
        } else {
            throw new Error("Either clientId must be set in the constructor");
        }

        if (options && options.sl) {
            this.sl = options.sl;
        }

        if (options && options.timeout) {
            this.timeout = options.timeout;
        }
        if (options && options.apiServers) {
            this.apiServers = options.apiServers;
        }
    }

    /**
     * Verify a key against the Yubico servers
     * @param otp {string} The OTP provided from the YubiKey to use to verify
     * @returns {Promise<Response>} The response instance that can be picked apart for values like the serial number
     */
    public async verify(otp: string): Promise<Response> {
        // Generate a nonce to send with the request
        // The Yubico docs state that the key can be between 16 and 40 characters long, so we
        // generate 20 bytes and convert it to 40 characters
        const nonce = crypto.randomUUID().replace(/-/g, "");

        // Generate the request params outside the http call so that we can generate the
        // hash for the request
        const requestParams = new URLSearchParams();

        // Append all of the required parameters
        requestParams.append("id", this.clientId);
        requestParams.append("otp", otp);
        requestParams.append("timestamp", "1");
        requestParams.append("nonce", nonce);

        if (this.sl) {
            requestParams.append("sl", this.sl as string);
        }

        if (this.timeout) {
            requestParams.append("timeout", this.timeout.toString());
        }

        // Sort them to properly allow for the security hash
        requestParams.sort();
        // Create and append the hash
        const hash = HmacSHA1(requestParams.toString(),  enc.Base64.parse(this.secret)).toString(enc.Base64)
        requestParams.append("h", hash);

        // Keep track of all the failed responses
        const failedResponses: Response[] = [];

        // Create an array of cancellations to allow for early stop should one server
        // respond successfully
        const cancellationCallbacks: Array<() => void> = [];
        const servers = this.apiServers || API_SERVERS
        const requestPromises = servers.map(
            (apiServer) =>
                new Promise<Response | undefined>(async (resolve) => {
                    // Create a URL object for the request
                    const url = new URL("https://" + apiServer + "/wsapi/2.0/verify");

                    // Set the search of the url to the request param string
                    url.search = requestParams.toString();
                    const req = await fetch(url.href).catch((err) => {
                        throw new Error("Failed to fetch from Yubico: " + err);
                    });
                    const res = await req.text();
                    resolve(Response.fromRawBody(res));
                }),
        );

        for await (const res of requestPromises) {
            // If there was no response, either the request was cancelled or the
            // network failed, so we can continue to the next one
            if (!res) {
                continue;
            }

            // Check the status to determine if we need to return it
            if (res.getStatus() === ResponseStatus.OK) {
                // Validate the response (this will throw if it fails)
                // If any one server fails to validate, everything should
                // fail because this means there is a possible man in the
                // middle attack.
                res.validate(nonce, this.secret, otp);
                // Cancel all of the remaining requests
                cancellationCallbacks.map((cb) => cb());

                return res;
            } else {
                // If the response status is not OK, push it on the failed responses array
                failedResponses.push(res);
            }
        }
        // If there were no failed responses (or successes as they would return)
        // throw a network error.
        if (failedResponses.length === 0) {
            throw new Error("Yubico API server network error");
        }

        // Validate one of the failed responses to throw the appropriate error
        failedResponses[0].validate(nonce, this.secret, otp);

        // Return the response if no error throws (this code should be unreachable)
        return failedResponses[0];
    }
}
