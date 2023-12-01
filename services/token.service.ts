import { ServiceSchema } from "../../../lib/types";

import DBMixin from "moleculer-db";
import SqlAdapter from "moleculer-db-adapter-sequelize";
import Sequelize from "sequelize";

import _ from "lodash";
import jwt from "jsonwebtoken";

(DBMixin as any).actions = {};

const Service: ServiceSchema = {
	name: "token",
	version: "api.v1",

	/**
	 * Mixins
	 */
	mixins: [DBMixin],

	adapter: new SqlAdapter(process.env.DATABASE_URL || "sqlite://:memory:"),

	model: {
		name: "token",
		define: {
			token: {
				type: Sequelize.STRING,
			},
			identity: {
				type: Sequelize.INTEGER,
			},
			service: {
				type: Sequelize.STRING, // service name who created the token and is responsible for it
			},
			expiresIn: {
				type: Sequelize.STRING,
			},
			createdBy: {
				type: Sequelize.STRING,
			},
			deleted: {
				type: Sequelize.BOOLEAN,
			},
			deletedAt: {
				type: Sequelize.DATE,
			},
		},
	},

	/**
	 * Service settings
	 */
	settings: {},

	/**
	 * Service dependencies
	 */
	// dependencies: [],

	/**
	 * Actions
	 */
	actions: {
		generate: {
			rest: "POST /generate",
			params: {
				payload: { type: "object", default: {}, optional: true },
				identity: {
					type: "number",
					positive: true,
					integer: true,
					min: 1,
					optional: true,
				},
				service: { type: "string" },
				expiresIn: {
					type: "enum",
					values: [
						"1h",
						"2h",
						"3h",
						"6h",
						"12h",
						"1d",
						"1w",
						"1m",
						"1y",
						"always",
					],
					default: "always",
				},
			},
			async handler(ctx) {
				try {
					const { payload, service, identity } = ctx.params;
					const creator = ctx.meta.creator.trim().toLowerCase();

					// get JWT_SECRET from config
					const configResponse: any = await ctx.call("api.v1.config.get", {
						key: "JWT_SECRET",
					});

					// check if config is valid
					if (configResponse.code != 200) {
						return configResponse;
					}

					const secret = configResponse.data.value;

					let options = {};

					if (ctx.params.expiresIn != "always") {
						options = {
							expiresIn: ctx.params.expiresIn,
						};
					}

					const token = jwt.sign(
						{
							...payload,
							identity,
							creator,
							service,
						},
						secret,
						options
					);

					await this.adapter.insert({
						token,
						identity,
						service,
						expiresIn: ctx.params.expiresIn,
						createdBy: creator,
						deleted: false,
						deletedAt: null,
					});

					return {
						code: 200,
						i18n: "TOKEN_GENERATED",
						data: {
							token,
							expiresIn: ctx.params.expiresIn,
						},
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		payload: {
			rest: "POST /payload",
			params: {
				token: { type: "string" },
			},
			async handler(ctx) {
				try {
					const token = ctx.params.token;

					// get JWT_SECRET from config
					const configResponse: any = await ctx.call("api.v1.config.get", {
						key: "JWT_SECRET",
					});

					// check if config is valid
					if (configResponse.code != 200) {
						return configResponse;
					}

					const secret = configResponse.data.value;

					let payload: any = {};

					try {
						payload = jwt.verify(token, secret);
					} catch (error) {
						// if error is expire
						if (error.name == "TokenExpiredError") {
							return {
								code: 400,
								i18n: "TOKEN_EXPIRED",
							};
						}

						// if error is invalid
						if (error.name == "JsonWebTokenError") {
							return {
								code: 400,
								i18n: "TOKEN_INVALID",
							};
						}
					}

					return {
						code: 200,
						i18n: "TOKEN_PAYLOAD",
						data: payload,
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		deleteByToken: {
			rest: "DELETE /delete/token",
			params: {
				token: { type: "string" },
			},
			async handler(ctx) {
				try {
					const token = ctx.params.token.trim().toLowerCase();
					const creator = ctx.meta.creator.trim().toLowerCase();

					// find token by token and createdBy
					const [tokens] = await this.adapter.db.query(
						`SELECT * FROM tokens WHERE token = '${token}' AND createdBy = '${creator}'`
					);

					if (tokens.length == 0) {
						return {
							code: 404,
							i18n: "TOKEN_NOT_FOUND",
						};
					}

					// delete token by updating deleted and deletedAt
					await this.adapter.db.query(
						`UPDATE tokens SET deleted = '0', deletedAt = datetime('now') WHERE id = '${tokens[0].id}'`
					);

					return {
						code: 200,
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		deleteByService: {
			rest: "DELETE /delete/service",
			params: {
				service: { type: "string" },
			},
			async handler(ctx) {
				try {
					const service = ctx.params.service;
					const creator = ctx.meta.creator.trim().toLowerCase();

					// delete token by updating deleted and deletedAt
					await this.adapter.db.query(
						`UPDATE tokens SET deleted = '0', deletedAt = datetime('now') WHERE service = '${service}' AND createdBy = '${creator}`
					);

					return {
						code: 200,
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		deleteByCreator: {
			rest: "DELETE /delete/creator",
			async handler(ctx) {
				try {
					const creator = ctx.meta.creator.trim().toLowerCase();

					// delete token by updating deleted and deletedAt
					await this.adapter.db.query(
						`UPDATE tokens SET deleted = '0', deletedAt = datetime('now') WHERE createdBy = '${creator}`
					);

					return {
						code: 200,
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		search: {
			rest: "POST /search",
			params: {
				service: { type: "string", optional: true },
				page: {
					type: "number",
					integer: true,
					positive: true,
					default: 1,
					optional: true,
				},
				limit: {
					type: "number",
					integer: true,
					positive: true,
					default: 10,
					optional: true,
				},
			},
			async handler(ctx) {
				try {
					const service = ctx.params.service;
					const creator = ctx.meta.creator.trim().toLowerCase();

					let sql = `SELECT * FROM tokens WHERE createdBy = '${creator}'`;

					if (service) {
						sql += ` AND service = '${service}'`;
					}

					sql += ` ORDER BY id DESC LIMIT ${ctx.params.limit} OFFSET ${
						(ctx.params.page - 1) * ctx.params.limit
					}`;

					const [tokens] = await this.adapter.db.query(sql);

					return {
						code: 200,
						i18n: "TOKENS_FOUND",
						meta: {
							page: ctx.params.page,
							limit: ctx.params.limit,
							total: tokens.length,
							last: Math.ceil(tokens.length / ctx.params.limit),
						},
						data: tokens.map((token: any) => ({
							...token,
							deleted: token.deleted == 1,
						})),
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		whoisthis: {
			rest: "POST /whoisthis",
			params: {
				token: { type: "string" },
				permissions: {
					type: "array",
					items: "string",
					default: [],
					optional: true,
				},
			},
			async handler(ctx) {
				try {
					const { token, permissions } = ctx.params;

					// get JWT_SECRET from config
					const configResponse: any = await ctx.call("api.v1.config.get", {
						key: "JWT_SECRET",
					});

					// check if config is valid
					if (configResponse.code != 200) {
						return configResponse;
					}

					const secret = configResponse.data.value;

					let payload: any = {};

					try {
						payload = jwt.verify(token, secret);
					} catch (error) {
						// if error is expire
						if (error.name == "TokenExpiredError") {
							return {
								code: 400,
								i18n: "TOKEN_EXPIRED",
							};
						}

						// if error is invalid
						if (error.name == "JsonWebTokenError") {
							return {
								code: 400,
								i18n: "TOKEN_INVALID",
							};
						}
					}

					const [resultPermissions, resultWhoisthis] = await Promise.all([
						this.getPermissions(ctx, permissions, payload),
						this.getWhoisthis(ctx, payload),
					]);

					if (resultPermissions.code != 200) {
						return resultPermissions;
					}

					if (resultPermissions.data.has == false) {
						return {
							code: 403,
							i18n: "ACCESS_DENIED",
							data: resultPermissions.data,
						};
					}

					if (resultWhoisthis.code != 200) {
						return resultWhoisthis;
					}

					return {
						code: 200,
						i18n: "TOKEN_PAYLOAD",
						data: {
							payload,
							permissions: resultPermissions.data,
							whoisthis: resultWhoisthis.data,
						},
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
	},

	/**
	 * Events
	 */
	events: {},

	/**
	 * Methods
	 */
	methods: {
		async getPermissions(ctx, permissions, payload) {
			if (permissions.length > 0 && payload.identity && payload.service) {
				const resultPermissions: any = await ctx.call("api.v1.permission.has", {
					identity: payload.identity,
					service: payload.service,
					permissions,
				});

				return resultPermissions;
			}

			return {
				code: 200,
				data: {
					has: true,
					permissions: [],
				},
			};
		},
		getWhoisthis(ctx, payload) {
			return ctx.call(`api.v1.${payload.service}.whoisthis`, {
				identity: payload.identity,
			});
		},
	},

	/**
	 * Service created lifecycle event handler
	 */
	// created() {},

	/**
	 * Service started lifecycle event handler
	 */
	// started() { },

	/**
	 * Service stopped lifecycle event handler
	 */
	// stopped() { }
};

export = Service;
