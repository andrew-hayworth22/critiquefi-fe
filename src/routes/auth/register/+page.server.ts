import  { type Actions, json, type RequestEvent } from '@sveltejs/kit';
import { register } from '$lib/server/api/auth';

export const actions: Actions = {
	default: async (event: RequestEvent) => {
		await register(event)
		json("ok")
	}
}