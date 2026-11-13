// FreeToolBuilder Worker: serves the website files and the /api/ accounts service.
import {onRequest} from "./api.js";
const SEC={
  "X-Content-Type-Options":"nosniff",
  "Referrer-Policy":"strict-origin-when-cross-origin",
  "X-Frame-Options":"SAMEORIGIN",
  "Strict-Transport-Security":"max-age=31536000; includeSubDomains",
  "Permissions-Policy":"geolocation=(self), camera=(self), microphone=(self), payment=(), usb=()",
  "Cross-Origin-Opener-Policy":"same-origin-allow-popups"
};
function withHeaders(res, url){
  const h=new Headers(res.headers);
  for(const k in SEC)h.set(k,SEC[k]);
  const p=url.pathname;
  if(url.searchParams.has("v")&&/\.(js|css)$/.test(p))h.set("Cache-Control","public, max-age=31536000, immutable");
  else if(/^\/(vendor|og)\//.test(p)||/\.(png|svg|webmanifest|mjs)$/.test(p))h.set("Cache-Control","public, max-age=604800");
  else if(p==="/sw.js")h.set("Cache-Control","no-cache");
  else if(/\.html$|\/$/.test(p))h.set("Cache-Control","public, max-age=0, must-revalidate");
  return new Response(res.body,{status:res.status,statusText:res.statusText,headers:h});
}
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.hostname.startsWith("www.")) { url.hostname = url.hostname.slice(4); return Response.redirect(url.toString(), 301); }
    if (url.pathname.startsWith("/api/")) {
      if (request.method==="POST"&&+(request.headers.get("content-length")||0)>10000) return new Response('{"error":"Too large"}',{status:413,headers:{"content-type":"application/json"}});
      const o=request.headers.get("origin");
      if (request.method==="POST"&&o&&new URL(o).host!==url.host) return new Response('{"error":"Not allowed"}',{status:403,headers:{"content-type":"application/json"}});
      const path = url.pathname.slice(5).split("/").filter(Boolean);
      const r=await onRequest({request, env, params: {path}});
      const h=new Headers(r.headers);for(const k in SEC)h.set(k,SEC[k]);
      return new Response(r.body,{status:r.status,headers:h});
    }
    return withHeaders(await env.ASSETS.fetch(request), url);
  }
};
