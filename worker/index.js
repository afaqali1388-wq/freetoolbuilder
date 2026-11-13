// FreeToolBuilder Worker: serves the website files and the /api/ accounts service.
import {onRequest} from "./api.js";
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      const path = url.pathname.slice(5).split("/").filter(Boolean);
      return onRequest({request, env, params: {path}});
    }
    return env.ASSETS.fetch(request);
  }
};
