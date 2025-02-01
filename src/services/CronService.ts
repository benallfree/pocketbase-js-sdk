import { BaseService } from "@/services/BaseService";
import { CommonOptions } from "@/tools/options";

export interface CronJob {
    id: string;
    expression: string;
}

export class CronService extends BaseService {
    /**
     * Returns list with all registered cron jobs.
     *
     * @throws {ClientResponseError}
     */
    getFullList(options?: CommonOptions): Array<CronJob> {
        options = Object.assign(
            {
                method: "GET",
            },
            options,
        );

        return this.client.send("/api/crons", options);
    }

    /**
     * Runs the specified cron job.
     *
     * @throws {ClientResponseError}
     */
    run(jobId: string, options?: CommonOptions): boolean {
        options = Object.assign(
            {
                method: "POST",
            },
            options,
        );

        this.client.send(`/api/crons/${encodeURIComponent(jobId)}`, options);
        return true;
    }
}
