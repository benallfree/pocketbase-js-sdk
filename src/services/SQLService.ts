import { BaseService } from "@/services/BaseService";
import { CommonOptions } from "@/tools/options";

export interface SQLResult {
    execTime: number;
    affectedRows: number;
    columns: Array<{ name: string; type: string; nullable: boolean }>;
    rows: Array<Array<string | null>>;
}

export class SQLService extends BaseService {
    /**
     * Executes the specified raw SQL query.
     * This operation is allowed only for superusers.
     *
     * @throws {ClientResponseError}
     */
    run(query: string, options?: CommonOptions): SQLResult {
        options = Object.assign(
            {
                method: "POST",
                body: { query },
            },
            options,
        );

        return this.client.send("/api/sql", options);
    }
}
