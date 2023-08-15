var PocketBase=function(){"use strict";function __awaiter(e,t,i,s){return new(i||(i=Promise))((function(n,o){function fulfilled(e){try{step(s.next(e))}catch(e){o(e)}}function rejected(e){try{step(s.throw(e))}catch(e){o(e)}}function step(e){e.done?n(e.value):function adopt(e){return e instanceof i?e:new i((function(t){t(e)}))}(e.value).then(fulfilled,rejected)}step((s=s.apply(e,t||[])).next())}))}"function"==typeof SuppressedError&&SuppressedError;class ClientResponseError extends Error{constructor(e){var t,i,s,n;super("ClientResponseError"),this.url="",this.status=0,this.response={},this.isAbort=!1,this.originalError=null,Object.setPrototypeOf(this,ClientResponseError.prototype),null!==e&&"object"==typeof e&&(this.url="string"==typeof e.url?e.url:"",this.status="number"==typeof e.status?e.status:0,this.isAbort=!!e.isAbort,this.originalError=e.originalError,null!==e.response&&"object"==typeof e.response?this.response=e.response:null!==e.data&&"object"==typeof e.data?this.response=e.data:this.response={}),this.originalError||e instanceof ClientResponseError||(this.originalError=e),"undefined"!=typeof DOMException&&e instanceof DOMException&&(this.isAbort=!0),this.name="ClientResponseError "+this.status,this.message=null===(t=this.response)||void 0===t?void 0:t.message,this.message||(this.isAbort?this.message="The request was autocancelled. You can find more info in https://github.com/pocketbase/js-sdk#auto-cancellation.":(null===(n=null===(s=null===(i=this.originalError)||void 0===i?void 0:i.cause)||void 0===s?void 0:s.message)||void 0===n?void 0:n.includes("ECONNREFUSED ::1"))?this.message="Failed to connect to the PocketBase server. Try changing the SDK URL from localhost to 127.0.0.1 (https://github.com/pocketbase/js-sdk/issues/21).":this.message="Something went wrong while processing your request.")}get data(){return this.response}toJSON(){return Object.assign({},this)}}const e=/^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;function cookieSerialize(t,i,s){const n=Object.assign({},s||{}),o=n.encode||defaultEncode;if(!e.test(t))throw new TypeError("argument name is invalid");const r=o(i);if(r&&!e.test(r))throw new TypeError("argument val is invalid");let a=t+"="+r;if(null!=n.maxAge){const e=n.maxAge-0;if(isNaN(e)||!isFinite(e))throw new TypeError("option maxAge is invalid");a+="; Max-Age="+Math.floor(e)}if(n.domain){if(!e.test(n.domain))throw new TypeError("option domain is invalid");a+="; Domain="+n.domain}if(n.path){if(!e.test(n.path))throw new TypeError("option path is invalid");a+="; Path="+n.path}if(n.expires){if(!function isDate(e){return"[object Date]"===Object.prototype.toString.call(e)||e instanceof Date}(n.expires)||isNaN(n.expires.valueOf()))throw new TypeError("option expires is invalid");a+="; Expires="+n.expires.toUTCString()}if(n.httpOnly&&(a+="; HttpOnly"),n.secure&&(a+="; Secure"),n.priority){switch("string"==typeof n.priority?n.priority.toLowerCase():n.priority){case"low":a+="; Priority=Low";break;case"medium":a+="; Priority=Medium";break;case"high":a+="; Priority=High";break;default:throw new TypeError("option priority is invalid")}}if(n.sameSite){switch("string"==typeof n.sameSite?n.sameSite.toLowerCase():n.sameSite){case!0:a+="; SameSite=Strict";break;case"lax":a+="; SameSite=Lax";break;case"strict":a+="; SameSite=Strict";break;case"none":a+="; SameSite=None";break;default:throw new TypeError("option sameSite is invalid")}}return a}function defaultDecode(e){return-1!==e.indexOf("%")?decodeURIComponent(e):e}function defaultEncode(e){return encodeURIComponent(e)}let t;function getTokenPayload(e){if(e)try{const i=decodeURIComponent(t(e.split(".")[1]).split("").map((function(e){return"%"+("00"+e.charCodeAt(0).toString(16)).slice(-2)})).join(""));return JSON.parse(i)||{}}catch(e){}return{}}t="function"==typeof atob?atob:e=>{let t=String(e).replace(/=+$/,"");if(t.length%4==1)throw new Error("'atob' failed: The string to be decoded is not correctly encoded.");for(var i,s,n=0,o=0,r="";s=t.charAt(o++);~s&&(i=n%4?64*i+s:s,n++%4)?r+=String.fromCharCode(255&i>>(-2*n&6)):0)s="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(s);return r};const i="pb_auth";class BaseAuthStore{constructor(){this.baseToken="",this.baseModel=null,this._onChangeCallbacks=[]}get token(){return this.baseToken}get model(){return this.baseModel}get isValid(){return!function isTokenExpired(e,t=0){let i=getTokenPayload(e);return!(Object.keys(i).length>0&&(!i.exp||i.exp-t>Date.now()/1e3))}(this.token)}get isAdmin(){return"admin"===getTokenPayload(this.token).type}get isAuthRecord(){return"authRecord"===getTokenPayload(this.token).type}save(e,t){this.baseToken=e||"",this.baseModel=t||null,this.triggerChange()}clear(){this.baseToken="",this.baseModel=null,this.triggerChange()}loadFromCookie(e,t=i){const s=function cookieParse(e,t){const i={};if("string"!=typeof e)return i;const s=Object.assign({},t||{}).decode||defaultDecode;let n=0;for(;n<e.length;){const t=e.indexOf("=",n);if(-1===t)break;let o=e.indexOf(";",n);if(-1===o)o=e.length;else if(o<t){n=e.lastIndexOf(";",t-1)+1;continue}const r=e.slice(n,t).trim();if(void 0===i[r]){let n=e.slice(t+1,o).trim();34===n.charCodeAt(0)&&(n=n.slice(1,-1));try{i[r]=s(n)}catch(e){i[r]=n}}n=o+1}return i}(e||"")[t]||"";let n={};try{n=JSON.parse(s),(null===typeof n||"object"!=typeof n||Array.isArray(n))&&(n={})}catch(e){}this.save(n.token||"",n.model||null)}exportToCookie(e,t=i){var s,n;const o={secure:!0,sameSite:!0,httpOnly:!0,path:"/"},r=getTokenPayload(this.token);(null==r?void 0:r.exp)?o.expires=new Date(1e3*r.exp):o.expires=new Date("1970-01-01"),e=Object.assign({},o,e);const a={token:this.token,model:this.model?JSON.parse(JSON.stringify(this.model)):null};let l=cookieSerialize(t,JSON.stringify(a),e);const c="undefined"!=typeof Blob?new Blob([l]).size:l.length;if(a.model&&c>4096){a.model={id:null===(s=null==a?void 0:a.model)||void 0===s?void 0:s.id,email:null===(n=null==a?void 0:a.model)||void 0===n?void 0:n.email};const i=["collectionId","username","verified"];for(const e in this.model)i.includes(e)&&(a.model[e]=this.model[e]);l=cookieSerialize(t,JSON.stringify(a),e)}return l}onChange(e,t=!1){return this._onChangeCallbacks.push(e),t&&e(this.token,this.model),()=>{for(let t=this._onChangeCallbacks.length-1;t>=0;t--)if(this._onChangeCallbacks[t]==e)return delete this._onChangeCallbacks[t],void this._onChangeCallbacks.splice(t,1)}}triggerChange(){for(const e of this._onChangeCallbacks)e&&e(this.token,this.model)}}class LocalAuthStore extends BaseAuthStore{constructor(e="pocketbase_auth"){super(),this.storageFallback={},this.storageKey=e,this._bindStorageEvent()}get token(){return(this._storageGet(this.storageKey)||{}).token||""}get model(){return(this._storageGet(this.storageKey)||{}).model||null}save(e,t){this._storageSet(this.storageKey,{token:e,model:t}),super.save(e,t)}clear(){this._storageRemove(this.storageKey),super.clear()}_storageGet(e){if("undefined"!=typeof window&&(null===window||void 0===window?void 0:window.localStorage)){const t=window.localStorage.getItem(e)||"";try{return JSON.parse(t)}catch(e){return t}}return this.storageFallback[e]}_storageSet(e,t){if("undefined"!=typeof window&&(null===window||void 0===window?void 0:window.localStorage)){let i=t;"string"!=typeof t&&(i=JSON.stringify(t)),window.localStorage.setItem(e,i)}else this.storageFallback[e]=t}_storageRemove(e){var t;"undefined"!=typeof window&&(null===window||void 0===window?void 0:window.localStorage)&&(null===(t=window.localStorage)||void 0===t||t.removeItem(e)),delete this.storageFallback[e]}_bindStorageEvent(){"undefined"!=typeof window&&(null===window||void 0===window?void 0:window.localStorage)&&window.addEventListener&&window.addEventListener("storage",(e=>{if(e.key!=this.storageKey)return;const t=this._storageGet(this.storageKey)||{};super.save(t.token||"",t.model||null)}))}}class BaseService{constructor(e){this.client=e}}class SettingsService extends BaseService{getAll(e){return e=Object.assign({method:"GET"},e),this.client.send("/api/settings",e)}update(e,t){return t=Object.assign({method:"PATCH",body:e},t),this.client.send("/api/settings",t)}testS3(e="storage",t){return t=Object.assign({method:"POST",body:{filesystem:e}},t),this.client.send("/api/settings/test/s3",t).then((()=>!0))}testEmail(e,t,i){return i=Object.assign({method:"POST",body:{email:e,template:t}},i),this.client.send("/api/settings/test/email",i).then((()=>!0))}generateAppleClientSecret(e,t,i,s,n,o){return o=Object.assign({method:"POST",body:{clientId:e,teamId:t,keyId:i,privateKey:s,duration:n}},o),this.client.send("/api/settings/apple/generate-client-secret",o)}}class CrudService extends BaseService{decode(e){return e}getFullList(e,t){if("number"==typeof e)return this._getFullList(e,t);let i=500;return(t=Object.assign({},e,t)).batch&&(i=t.batch,delete t.batch),this._getFullList(i,t)}getList(e=1,t=30,i){return(i=Object.assign({method:"GET"},i)).query=Object.assign({page:e,perPage:t},i.query),this.client.send(this.baseCrudPath,i).then((e=>{var t;return e.items=(null===(t=e.items)||void 0===t?void 0:t.map((e=>this.decode(e))))||[],e}))}getFirstListItem(e,t){return(t=Object.assign({requestKey:"one_by_filter_"+this.baseCrudPath+"_"+e},t)).query=Object.assign({filter:e,skipTotal:1},t.query),this.getList(1,1,t).then((e=>{var t;if(!(null===(t=null==e?void 0:e.items)||void 0===t?void 0:t.length))throw new ClientResponseError({status:404,data:{code:404,message:"The requested resource wasn't found.",data:{}}});return e.items[0]}))}getOne(e,t){return t=Object.assign({method:"GET"},t),this.client.send(this.baseCrudPath+"/"+encodeURIComponent(e),t).then((e=>this.decode(e)))}create(e,t){return t=Object.assign({method:"POST",body:e},t),this.client.send(this.baseCrudPath,t).then((e=>this.decode(e)))}update(e,t,i){return i=Object.assign({method:"PATCH",body:t},i),this.client.send(this.baseCrudPath+"/"+encodeURIComponent(e),i).then((e=>this.decode(e)))}delete(e,t){return t=Object.assign({method:"DELETE"},t),this.client.send(this.baseCrudPath+"/"+encodeURIComponent(e),t).then((()=>!0))}_getFullList(e=500,t){(t=t||{}).query=Object.assign({skipTotal:1},t.query);let i=[],request=s=>__awaiter(this,void 0,void 0,(function*(){return this.getList(s,e||500,t).then((e=>{const t=e.items;return i=i.concat(t),t.length==e.perPage?request(s+1):i}))}));return request(1)}}function normalizeLegacyOptionsArgs(e,t,i,s){const n=void 0!==s;return n||void 0!==i?n?(console.warn(e),t.body=Object.assign({},t.body,i),t.query=Object.assign({},t.query,s),t):t=Object.assign(t,i):t}class AdminService extends CrudService{get baseCrudPath(){return"/api/admins"}update(e,t,i){return super.update(e,t,i).then((e=>{var t,i;return(null===(t=this.client.authStore.model)||void 0===t?void 0:t.id)===e.id&&void 0===(null===(i=this.client.authStore.model)||void 0===i?void 0:i.collectionId)&&this.client.authStore.save(this.client.authStore.token,e),e}))}delete(e,t){return super.delete(e,t).then((t=>{var i,s;return t&&(null===(i=this.client.authStore.model)||void 0===i?void 0:i.id)===e&&void 0===(null===(s=this.client.authStore.model)||void 0===s?void 0:s.collectionId)&&this.client.authStore.clear(),t}))}authResponse(e){const t=this.decode((null==e?void 0:e.admin)||{});return(null==e?void 0:e.token)&&(null==e?void 0:e.admin)&&this.client.authStore.save(e.token,t),Object.assign({},e,{token:(null==e?void 0:e.token)||"",admin:t})}authWithPassword(e,t,i,s){let n={method:"POST",body:{identity:e,password:t}};return n=normalizeLegacyOptionsArgs("This form of authWithPassword(email, pass, body?, query?) is depreacted. Consider replacing it with authWithPassword(email, pass, options?).",n,i,s),this.client.send(this.baseCrudPath+"/auth-with-password",n).then(this.authResponse.bind(this))}authRefresh(e,t){let i={method:"POST"};return i=normalizeLegacyOptionsArgs("This form of authRefresh(body?, query?) is depreacted. Consider replacing it with authRefresh(options?).",i,e,t),this.client.send(this.baseCrudPath+"/auth-refresh",i).then(this.authResponse.bind(this))}requestPasswordReset(e,t,i){let s={method:"POST",body:{email:e}};return s=normalizeLegacyOptionsArgs("This form of requestPasswordReset(email, body?, query?) is depreacted. Consider replacing it with requestPasswordReset(email, options?).",s,t,i),this.client.send(this.baseCrudPath+"/request-password-reset",s).then((()=>!0))}confirmPasswordReset(e,t,i,s,n){let o={method:"POST",body:{token:e,password:t,passwordConfirm:i}};return o=normalizeLegacyOptionsArgs("This form of confirmPasswordReset(resetToken, password, passwordConfirm, body?, query?) is depreacted. Consider replacing it with confirmPasswordReset(resetToken, password, passwordConfirm, options?).",o,s,n),this.client.send(this.baseCrudPath+"/confirm-password-reset",o).then((()=>!0))}}class RecordService extends CrudService{constructor(e,t){super(e),this.collectionIdOrName=t}get baseCrudPath(){return this.baseCollectionPath+"/records"}get baseCollectionPath(){return"/api/collections/"+encodeURIComponent(this.collectionIdOrName)}subscribeOne(e,t){return __awaiter(this,void 0,void 0,(function*(){return console.warn("PocketBase: subscribeOne(recordId, callback) is deprecated. Please replace it with subscribe(recordId, callback)."),this.client.realtime.subscribe(this.collectionIdOrName+"/"+e,t)}))}subscribe(e,t){return __awaiter(this,void 0,void 0,(function*(){if("function"==typeof e)return console.warn("PocketBase: subscribe(callback) is deprecated. Please replace it with subscribe('*', callback)."),this.client.realtime.subscribe(this.collectionIdOrName,e);if(!t)throw new Error("Missing subscription callback.");if(""===e)throw new Error("Missing topic.");let i=this.collectionIdOrName;return"*"!==e&&(i+="/"+e),this.client.realtime.subscribe(i,t)}))}unsubscribe(e){return __awaiter(this,void 0,void 0,(function*(){return"*"===e?this.client.realtime.unsubscribe(this.collectionIdOrName):e?this.client.realtime.unsubscribe(this.collectionIdOrName+"/"+e):this.client.realtime.unsubscribeByPrefix(this.collectionIdOrName)}))}getFullList(e,t){if("number"==typeof e)return super.getFullList(e,t);const i=Object.assign({},e,t);return super.getFullList(i)}getList(e=1,t=30,i){return super.getList(e,t,i)}getFirstListItem(e,t){return super.getFirstListItem(e,t)}getOne(e,t){return super.getOne(e,t)}create(e,t){return super.create(e,t)}update(e,t,i){return super.update(e,t,i).then((e=>{var t,i,s;return(null===(t=this.client.authStore.model)||void 0===t?void 0:t.id)!==(null==e?void 0:e.id)||(null===(i=this.client.authStore.model)||void 0===i?void 0:i.collectionId)!==this.collectionIdOrName&&(null===(s=this.client.authStore.model)||void 0===s?void 0:s.collectionName)!==this.collectionIdOrName||this.client.authStore.save(this.client.authStore.token,e),e}))}delete(e,t){return super.delete(e,t).then((t=>{var i,s,n;return!t||(null===(i=this.client.authStore.model)||void 0===i?void 0:i.id)!==e||(null===(s=this.client.authStore.model)||void 0===s?void 0:s.collectionId)!==this.collectionIdOrName&&(null===(n=this.client.authStore.model)||void 0===n?void 0:n.collectionName)!==this.collectionIdOrName||this.client.authStore.clear(),t}))}authResponse(e){const t=this.decode((null==e?void 0:e.record)||{});return this.client.authStore.save(null==e?void 0:e.token,t),Object.assign({},e,{token:(null==e?void 0:e.token)||"",record:t})}listAuthMethods(e){return e=Object.assign({method:"GET"},e),this.client.send(this.baseCollectionPath+"/auth-methods",e).then((e=>Object.assign({},e,{usernamePassword:!!(null==e?void 0:e.usernamePassword),emailPassword:!!(null==e?void 0:e.emailPassword),authProviders:Array.isArray(null==e?void 0:e.authProviders)?null==e?void 0:e.authProviders:[]})))}authWithPassword(e,t,i,s){let n={method:"POST",body:{identity:e,password:t}};return n=normalizeLegacyOptionsArgs("This form of authWithPassword(usernameOrEmail, pass, body?, query?) is depreacted. Consider replacing it with authWithPassword(usernameOrEmail, pass, options?).",n,i,s),this.client.send(this.baseCollectionPath+"/auth-with-password",n).then((e=>this.authResponse(e)))}authWithOAuth2Code(e,t,i,s,n,o,r){let a={method:"POST",body:{provider:e,code:t,codeVerifier:i,redirectUrl:s,createData:n}};return a=normalizeLegacyOptionsArgs("This form of authWithOAuth2Code(provider, code, codeVerifier, redirectUrl, createData?, body?, query?) is depreacted. Consider replacing it with authWithOAuth2Code(provider, code, codeVerifier, redirectUrl, createData?, options?).",a,o,r),this.client.send(this.baseCollectionPath+"/auth-with-oauth2",a).then((e=>this.authResponse(e)))}authWithOAuth2(...e){return __awaiter(this,void 0,void 0,(function*(){if(e.length>1||"string"==typeof(null==e?void 0:e[0]))return console.warn("PocketBase: This form of authWithOAuth2() is deprecated and may get removed in the future. Please replace with authWithOAuth2Code() OR use the authWithOAuth2() realtime form as shown in https://pocketbase.io/docs/authentication/#oauth2-integration."),this.authWithOAuth2Code((null==e?void 0:e[0])||"",(null==e?void 0:e[1])||"",(null==e?void 0:e[2])||"",(null==e?void 0:e[3])||"",(null==e?void 0:e[4])||{},(null==e?void 0:e[5])||{},(null==e?void 0:e[6])||{});const t=(null==e?void 0:e[0])||{},i=(yield this.listAuthMethods()).authProviders.find((e=>e.name===t.provider));if(!i)throw new ClientResponseError(new Error(`Missing or invalid provider "${t.provider}".`));const s=this.client.buildUrl("/api/oauth2-redirect");return new Promise(((e,n)=>__awaiter(this,void 0,void 0,(function*(){var o;try{const r=yield this.client.realtime.subscribe("@oauth2",(o=>__awaiter(this,void 0,void 0,(function*(){const a=this.client.realtime.clientId;try{if(r(),!o.state||a!==o.state)throw new Error("State parameters don't match.");const n=Object.assign({},t);delete n.provider,delete n.scopes,delete n.createData,delete n.urlCallback;const l=yield this.authWithOAuth2Code(i.name,o.code,i.codeVerifier,s,t.createData,n);e(l)}catch(e){n(new ClientResponseError(e))}})))),a={state:this.client.realtime.clientId};(null===(o=t.scopes)||void 0===o?void 0:o.length)&&(a.scope=t.scopes.join(" "));const l=this._replaceQueryParams(i.authUrl+s,a);yield t.urlCallback?t.urlCallback(l):this._defaultUrlCallback(l)}catch(e){n(new ClientResponseError(e))}}))))}))}authRefresh(e,t){let i={method:"POST"};return i=normalizeLegacyOptionsArgs("This form of authRefresh(body?, query?) is depreacted. Consider replacing it with authRefresh(options?).",i,e,t),this.client.send(this.baseCollectionPath+"/auth-refresh",i).then((e=>this.authResponse(e)))}requestPasswordReset(e,t,i){let s={method:"POST",body:{email:e}};return s=normalizeLegacyOptionsArgs("This form of requestPasswordReset(email, body?, query?) is depreacted. Consider replacing it with requestPasswordReset(email, options?).",s,t,i),this.client.send(this.baseCollectionPath+"/request-password-reset",s).then((()=>!0))}confirmPasswordReset(e,t,i,s,n){let o={method:"POST",body:{token:e,password:t,passwordConfirm:i}};return o=normalizeLegacyOptionsArgs("This form of confirmPasswordReset(token, password, passwordConfirm, body?, query?) is depreacted. Consider replacing it with confirmPasswordReset(token, password, passwordConfirm, options?).",o,s,n),this.client.send(this.baseCollectionPath+"/confirm-password-reset",o).then((()=>!0))}requestVerification(e,t,i){let s={method:"POST",body:{email:e}};return s=normalizeLegacyOptionsArgs("This form of requestVerification(email, body?, query?) is depreacted. Consider replacing it with requestVerification(email, options?).",s,t,i),this.client.send(this.baseCollectionPath+"/request-verification",s).then((()=>!0))}confirmVerification(e,t,i){let s={method:"POST",body:{token:e}};return s=normalizeLegacyOptionsArgs("This form of confirmVerification(token, body?, query?) is depreacted. Consider replacing it with confirmVerification(token, options?).",s,t,i),this.client.send(this.baseCollectionPath+"/confirm-verification",s).then((()=>!0))}requestEmailChange(e,t,i){let s={method:"POST",body:{newEmail:e}};return s=normalizeLegacyOptionsArgs("This form of requestEmailChange(newEmail, body?, query?) is depreacted. Consider replacing it with requestEmailChange(newEmail, options?).",s,t,i),this.client.send(this.baseCollectionPath+"/request-email-change",s).then((()=>!0))}confirmEmailChange(e,t,i,s){let n={method:"POST",body:{token:e,password:t}};return n=normalizeLegacyOptionsArgs("This form of confirmEmailChange(token, password, body?, query?) is depreacted. Consider replacing it with confirmEmailChange(token, password, options?).",n,i,s),this.client.send(this.baseCollectionPath+"/confirm-email-change",n).then((()=>!0))}listExternalAuths(e,t){return t=Object.assign({method:"GET"},t),this.client.send(this.baseCrudPath+"/"+encodeURIComponent(e)+"/external-auths",t)}unlinkExternalAuth(e,t,i){return i=Object.assign({method:"DELETE"},i),this.client.send(this.baseCrudPath+"/"+encodeURIComponent(e)+"/external-auths/"+encodeURIComponent(t),i).then((()=>!0))}_replaceQueryParams(e,t={}){let i=e,s="";e.indexOf("?")>=0&&(i=e.substring(0,e.indexOf("?")),s=e.substring(e.indexOf("?")+1));const n={},o=s.split("&");for(const e of o){if(""==e)continue;const t=e.split("=");n[decodeURIComponent(t[0].replace(/\+/g," "))]=decodeURIComponent((t[1]||"").replace(/\+/g," "))}for(let e in t)t.hasOwnProperty(e)&&(null==t[e]?delete n[e]:n[e]=t[e]);s="";for(let e in n)n.hasOwnProperty(e)&&(""!=s&&(s+="&"),s+=encodeURIComponent(e.replace(/%20/g,"+"))+"="+encodeURIComponent(n[e].replace(/%20/g,"+")));return""!=s?i+"?"+s:i}_defaultUrlCallback(e){if("undefined"==typeof window||!(null===window||void 0===window?void 0:window.open))throw new ClientResponseError(new Error("Not in a browser context - please pass a custom urlCallback function."));let t=1024,i=768,s=window.innerWidth,n=window.innerHeight;t=t>s?s:t,i=i>n?n:i;let o=s/2-t/2,r=n/2-i/2;window.open(e,"oauth2-popup","width="+t+",height="+i+",top="+r+",left="+o+",resizable,menubar=no")}}class CollectionService extends CrudService{get baseCrudPath(){return"/api/collections"}import(e,t=!1,i){return __awaiter(this,void 0,void 0,(function*(){return i=Object.assign({method:"PUT",body:{collections:e,deleteMissing:t}},i),this.client.send(this.baseCrudPath+"/import",i).then((()=>!0))}))}}class LogService extends BaseService{getRequestsList(e=1,t=30,i){return(i=Object.assign({method:"GET"},i)).query=Object.assign({page:e,perPage:t},i.query),this.client.send("/api/logs/requests",i)}getRequest(e,t){return t=Object.assign({method:"GET"},t),this.client.send("/api/logs/requests/"+encodeURIComponent(e),t)}getRequestsStats(e){return e=Object.assign({method:"GET"},e),this.client.send("/api/logs/requests/stats",e)}}class RealtimeService extends BaseService{constructor(){super(...arguments),this.clientId="",this.eventSource=null,this.subscriptions={},this.lastSentTopics=[],this.maxConnectTimeout=15e3,this.reconnectAttempts=0,this.maxReconnectAttempts=1/0,this.predefinedReconnectIntervals=[200,300,500,1e3,1200,1500,2e3],this.pendingConnects=[]}get isConnected(){return!!this.eventSource&&!!this.clientId&&!this.pendingConnects.length}subscribe(e,t){var i;return __awaiter(this,void 0,void 0,(function*(){if(!e)throw new Error("topic must be set.");const listener=function(e){const i=e;let s;try{s=JSON.parse(null==i?void 0:i.data)}catch(e){}t(s||{})};return this.subscriptions[e]||(this.subscriptions[e]=[]),this.subscriptions[e].push(listener),this.isConnected?1===this.subscriptions[e].length?yield this.submitSubscriptions():null===(i=this.eventSource)||void 0===i||i.addEventListener(e,listener):yield this.connect(),()=>__awaiter(this,void 0,void 0,(function*(){return this.unsubscribeByTopicAndListener(e,listener)}))}))}unsubscribe(e){var t;return __awaiter(this,void 0,void 0,(function*(){if(this.hasSubscriptionListeners(e)){if(e){for(let i of this.subscriptions[e])null===(t=this.eventSource)||void 0===t||t.removeEventListener(e,i);delete this.subscriptions[e]}else this.subscriptions={};this.hasSubscriptionListeners()?this.hasSubscriptionListeners(e)||(yield this.submitSubscriptions()):this.disconnect()}}))}unsubscribeByPrefix(e){var t;return __awaiter(this,void 0,void 0,(function*(){let i=!1;for(let s in this.subscriptions)if(s.startsWith(e)){i=!0;for(let e of this.subscriptions[s])null===(t=this.eventSource)||void 0===t||t.removeEventListener(s,e);delete this.subscriptions[s]}i&&(this.hasSubscriptionListeners()?yield this.submitSubscriptions():this.disconnect())}))}unsubscribeByTopicAndListener(e,t){var i;return __awaiter(this,void 0,void 0,(function*(){if(!Array.isArray(this.subscriptions[e])||!this.subscriptions[e].length)return;let s=!1;for(let n=this.subscriptions[e].length-1;n>=0;n--)this.subscriptions[e][n]===t&&(s=!0,delete this.subscriptions[e][n],this.subscriptions[e].splice(n,1),null===(i=this.eventSource)||void 0===i||i.removeEventListener(e,t));s&&(this.subscriptions[e].length||delete this.subscriptions[e],this.hasSubscriptionListeners()?this.hasSubscriptionListeners(e)||(yield this.submitSubscriptions()):this.disconnect())}))}hasSubscriptionListeners(e){var t,i;if(this.subscriptions=this.subscriptions||{},e)return!!(null===(t=this.subscriptions[e])||void 0===t?void 0:t.length);for(let e in this.subscriptions)if(null===(i=this.subscriptions[e])||void 0===i?void 0:i.length)return!0;return!1}submitSubscriptions(){return __awaiter(this,void 0,void 0,(function*(){if(this.clientId)return this.addAllSubscriptionListeners(),this.lastSentTopics=this.getNonEmptySubscriptionTopics(),this.client.send("/api/realtime",{method:"POST",body:{clientId:this.clientId,subscriptions:this.lastSentTopics},query:{requestKey:this.getSubscriptionsCancelKey()}}).catch((e=>{if(!(null==e?void 0:e.isAbort))throw e}))}))}getSubscriptionsCancelKey(){return"realtime_"+this.clientId}getNonEmptySubscriptionTopics(){const e=[];for(let t in this.subscriptions)this.subscriptions[t].length&&e.push(t);return e}addAllSubscriptionListeners(){if(this.eventSource){this.removeAllSubscriptionListeners();for(let e in this.subscriptions)for(let t of this.subscriptions[e])this.eventSource.addEventListener(e,t)}}removeAllSubscriptionListeners(){if(this.eventSource)for(let e in this.subscriptions)for(let t of this.subscriptions[e])this.eventSource.removeEventListener(e,t)}connect(){return __awaiter(this,void 0,void 0,(function*(){if(!(this.reconnectAttempts>0))return new Promise(((e,t)=>{this.pendingConnects.push({resolve:e,reject:t}),this.pendingConnects.length>1||this.initConnect()}))}))}initConnect(){this.disconnect(!0),clearTimeout(this.connectTimeoutId),this.connectTimeoutId=setTimeout((()=>{this.connectErrorHandler(new Error("EventSource connect took too long."))}),this.maxConnectTimeout),this.eventSource=new EventSource(this.client.buildUrl("/api/realtime")),this.eventSource.onerror=e=>{this.connectErrorHandler(new Error("Failed to establish realtime connection."))},this.eventSource.addEventListener("PB_CONNECT",(e=>{const t=e;this.clientId=null==t?void 0:t.lastEventId,this.submitSubscriptions().then((()=>__awaiter(this,void 0,void 0,(function*(){let e=3;for(;this.hasUnsentSubscriptions()&&e>0;)e--,yield this.submitSubscriptions()})))).then((()=>{for(let e of this.pendingConnects)e.resolve();this.pendingConnects=[],this.reconnectAttempts=0,clearTimeout(this.reconnectTimeoutId),clearTimeout(this.connectTimeoutId)})).catch((e=>{this.clientId="",this.connectErrorHandler(e)}))}))}hasUnsentSubscriptions(){const e=this.getNonEmptySubscriptionTopics();if(e.length!=this.lastSentTopics.length)return!0;for(const t of e)if(!this.lastSentTopics.includes(t))return!0;return!1}connectErrorHandler(e){if(clearTimeout(this.connectTimeoutId),clearTimeout(this.reconnectTimeoutId),!this.clientId&&!this.reconnectAttempts||this.reconnectAttempts>this.maxReconnectAttempts){for(let t of this.pendingConnects)t.reject(new ClientResponseError(e));return this.pendingConnects=[],void this.disconnect()}this.disconnect(!0);const t=this.predefinedReconnectIntervals[this.reconnectAttempts]||this.predefinedReconnectIntervals[this.predefinedReconnectIntervals.length-1];this.reconnectAttempts++,this.reconnectTimeoutId=setTimeout((()=>{this.initConnect()}),t)}disconnect(e=!1){var t;if(clearTimeout(this.connectTimeoutId),clearTimeout(this.reconnectTimeoutId),this.removeAllSubscriptionListeners(),this.client.cancelRequest(this.getSubscriptionsCancelKey()),null===(t=this.eventSource)||void 0===t||t.close(),this.eventSource=null,this.clientId="",!e){this.reconnectAttempts=0;for(let e of this.pendingConnects)e.resolve();this.pendingConnects=[]}}}class HealthService extends BaseService{check(e){return e=Object.assign({method:"GET"},e),this.client.send("/api/health",e)}}class FileService extends BaseService{getUrl(e,t,i={}){const s=[];s.push("api"),s.push("files"),s.push(encodeURIComponent(e.collectionId||e.collectionName)),s.push(encodeURIComponent(e.id)),s.push(encodeURIComponent(t));let n=this.client.buildUrl(s.join("/"));if(Object.keys(i).length){!1===i.download&&delete i.download;const e=new URLSearchParams(i);n+=(n.includes("?")?"&":"?")+e}return n}getToken(e){return e=Object.assign({method:"POST"},e),this.client.send("/api/files/token",e).then((e=>(null==e?void 0:e.token)||""))}}class BackupService extends BaseService{getFullList(e){return e=Object.assign({method:"GET"},e),this.client.send("/api/backups",e)}create(e,t){return t=Object.assign({method:"POST",body:{name:e}},t),this.client.send("/api/backups",t).then((()=>!0))}delete(e,t){return t=Object.assign({method:"DELETE"},t),this.client.send(`/api/backups/${encodeURIComponent(e)}`,t).then((()=>!0))}restore(e,t){return t=Object.assign({method:"POST"},t),this.client.send(`/api/backups/${encodeURIComponent(e)}/restore`,t).then((()=>!0))}getDownloadUrl(e,t){return this.client.buildUrl(`/api/backups/${encodeURIComponent(t)}?token=${encodeURIComponent(e)}`)}}const s=["requestKey","$cancelKey","$autoCancel","fetch","headers","body","query","params","cache","credentials","headers","integrity","keepalive","method","mode","redirect","referrer","referrerPolicy","signal","window"];return class Client{constructor(e="/",t,i="en-US"){this.cancelControllers={},this.recordServices={},this.enableAutoCancellation=!0,this.baseUrl=e,this.lang=i,this.authStore=t||new LocalAuthStore,this.admins=new AdminService(this),this.collections=new CollectionService(this),this.files=new FileService(this),this.logs=new LogService(this),this.settings=new SettingsService(this),this.realtime=new RealtimeService(this),this.health=new HealthService(this),this.backups=new BackupService(this)}collection(e){return this.recordServices[e]||(this.recordServices[e]=new RecordService(this,e)),this.recordServices[e]}autoCancellation(e){return this.enableAutoCancellation=!!e,this}cancelRequest(e){return this.cancelControllers[e]&&(this.cancelControllers[e].abort(),delete this.cancelControllers[e]),this}cancelAllRequests(){for(let e in this.cancelControllers)this.cancelControllers[e].abort();return this.cancelControllers={},this}getFileUrl(e,t,i={}){return this.files.getUrl(e,t,i)}buildUrl(e){var t;let i=this.baseUrl;return"undefined"==typeof window||!window.location||i.startsWith("https://")||i.startsWith("http://")||(i=(null===(t=window.location.origin)||void 0===t?void 0:t.endsWith("/"))?window.location.origin.substring(0,window.location.origin.length-1):window.location.origin||"",this.baseUrl.startsWith("/")||(i+=window.location.pathname||"/",i+=i.endsWith("/")?"":"/"),i+=this.baseUrl),e&&(i+=i.endsWith("/")?"":"/",i+=e.startsWith("/")?e.substring(1):e),i}send(e,t){return __awaiter(this,void 0,void 0,(function*(){t=this.initSendOptions(e,t);let i=this.buildUrl(e);if(void 0!==t.query){const e=this.serializeQueryParams(t.query);e&&(i+=(i.includes("?")?"&":"?")+e),delete t.query}if(this.beforeSend){const e=Object.assign({},yield this.beforeSend(i,t));void 0!==e.url||void 0!==e.options?(i=e.url||i,t=e.options||t):Object.keys(e).length&&(t=e,(null===console||void 0===console?void 0:console.warn)&&console.warn("Deprecated format of beforeSend return: please use `return { url, options }`, instead of `return options`."))}"application/json"==this.getHeader(t.headers,"Content-Type")&&t.body&&"string"!=typeof t.body&&(t.body=JSON.stringify(t.body));return(t.fetch||fetch)(i,t).then((e=>__awaiter(this,void 0,void 0,(function*(){let t={};try{t=yield e.json()}catch(e){}if(this.afterSend&&(t=yield this.afterSend(e,t)),e.status>=400)throw new ClientResponseError({url:e.url,status:e.status,data:t});return t})))).catch((e=>{throw new ClientResponseError(e)}))}))}initSendOptions(e,t){(t=Object.assign({method:"GET"},t)).query=t.query||{},t.body=this.convertToFormDataIfNeeded(t.body);for(let e in t)s.includes(e)||(t.query[e]=t[e],delete t[e]);if(t.query=Object.assign({},t.params,t.query),void 0===t.requestKey&&(!1===t.$autoCancel||!1===t.query.$autoCancel?t.requestKey=null:(t.$cancelKey||t.query.$cancelKey)&&(t.requestKey=t.$cancelKey||t.query.$cancelKey)),delete t.$autoCancel,delete t.query.$autoCancel,delete t.$cancelKey,delete t.query.$cancelKey,null!==this.getHeader(t.headers,"Content-Type")||this.isFormData(t.body)||(t.headers=Object.assign({},t.headers,{"Content-Type":"application/json"})),null===this.getHeader(t.headers,"Accept-Language")&&(t.headers=Object.assign({},t.headers,{"Accept-Language":this.lang})),this.authStore.token&&null===this.getHeader(t.headers,"Authorization")&&(t.headers=Object.assign({},t.headers,{Authorization:this.authStore.token})),this.enableAutoCancellation&&null!==t.requestKey){const i=t.requestKey||(t.method||"GET")+e;this.cancelRequest(i);const s=new AbortController;this.cancelControllers[i]=s,t.signal=s.signal}return t}convertToFormDataIfNeeded(e){if("undefined"==typeof FormData||void 0===e||"object"!=typeof e||null===e||this.isFormData(e)||!this.hasBlobField(e))return e;const t=new FormData;for(let i in e)t.append(i,e[i]);return t}hasBlobField(e){for(let t in e){const i=Array.isArray(e[t])?e[t]:[e[t]];for(let e of i)if("undefined"!=typeof Blob&&e instanceof Blob||"undefined"!=typeof File&&e instanceof File)return!0}return!1}getHeader(e,t){e=e||{},t=t.toLowerCase();for(let i in e)if(i.toLowerCase()==t)return e[i];return null}isFormData(e){return e&&("FormData"===e.constructor.name||"undefined"!=typeof FormData&&e instanceof FormData)}serializeQueryParams(e){const t=[];for(const i in e){if(null===e[i])continue;const s=e[i],n=encodeURIComponent(i);if(Array.isArray(s))for(const e of s)t.push(n+"="+encodeURIComponent(e));else s instanceof Date?t.push(n+"="+encodeURIComponent(s.toISOString())):null!==typeof s&&"object"==typeof s?t.push(n+"="+encodeURIComponent(JSON.stringify(s))):t.push(n+"="+encodeURIComponent(s))}return t.join("&")}}}();
//# sourceMappingURL=pocketbase.iife.js.map
