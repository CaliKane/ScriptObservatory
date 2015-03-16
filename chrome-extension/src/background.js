/*
 *
 * This file (background.js) implements the basic ScriptObservatory functionality.
 *
 * The content here is loaded in the background within the "background page" Chrome sets up for
 * the extension. The main functionality is implemented within the chrome.webRequest.onBeforeRequest
 * listener, which is called by the browser whenever a request is about to be made.
 *
 */


/* 
 * CONSTANTS
 */
API_BASE_URL = "http://127.0.0.1:8080/api/script";


/*
 * httpGet(url) - Perform a HTTP GET request to *url* and return its content
 */
function httpGet(url){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, false);
    xmlHttp.send();
    return xmlHttp.responseText;  // TODO: check return code
}


/*
 * httpPost(url, data) - Send json-ified *data* with a HTTP POST request to *url*
 */
function httpPost(url, data){
    var request = new XMLHttpRequest();
    request.open("POST", url, true);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(data));
    return;  // TODO: check return code
}


/*
 * makeIdString(tabId, frameId)) - Create a unique ID string from *tabId* and *frameId*
 *
 * this is used to try to detect the parent frame that is responsible for a given request.
 * frameId is only unique on a per-tab basis, so both are needed.
 *
 * more info: https://developer.chrome.com/extensions/webRequest
 */
function makeIdString(tabId, frameId){
    return tabId + "-" + frameId;
}


/* 
 * We hook into chrome.webRequest.onBeforeRequest to perform our own download of the content and calculate the
 * sha256 hash of the content. After the download is complete, we POST the url & hash value to *API_BASE_URL* 
 * and embed the content in the webpage by changing the URL to a data URI object (avoids downloading content twice).
 * 
 * It would be nice if we could let the browser do the request normally and grab the content of its response,
 * but this is not currently possible with the chrome APIs. 
 *
 * This functionality is discussed in the following issue: 
 *   https://code.google.com/p/chromium/issues/detail?id=104058
 * 
 * A draft proposal for adding this functionality is here: 
 *   https://groups.google.com/a/chromium.org/forum/#!msg/apps-dev/v176iCmRgSs/iM-72Evf8JgJ
 *
 * More information is available in the chrome.webRequest docs: 
 *   https://developer.chrome.com/extensions/webRequest
 */
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        var data = httpGet(details.url);

        var hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);

        var parent_url = "n/a";
        var id_string = makeIdString(details.tabId, details.frameId);
        if (id_string in PARENT_URLS){
            parent_url = PARENT_URLS[id_string];
        }

        var post_data = {"url": details.url, 
                         "parent_url": parent_url,
                         "sha256": hash, 
                         "date": details.timeStamp};

        // TODO batch URL & SHA256 to be sent off to server
        
        httpPost(API_BASE_URL, post_data);

        return {"redirectUrl":"data:text/html;base64, " + window.btoa(data)};
    }, 
    {urls: ["<all_urls>"], types: ["script"]}, 
    ["blocking"]
);


/*
 * PARENT_URLS and the chrome.webRequest.onResponseStarted listener are an ugly hack 
 * to try to keep track of the URL of each page that could possibly spawn a javascript
 * request later on.
 * 
 * Once the onBeforeRequest listener is expanded to grab all types of pages, the URLs
 * and parent/children relationships should be recorded there...
 * 
 * The current setup will fail in cases like news.ycombinator.com, where the initial
 * request actually returns a javascript object that then pulls down the page content.
 */

PARENT_URLS = {};

chrome.webRequest.onResponseStarted.addListener(
    function(details){
        var id_string = makeIdString(details.tabId, details.frameId);
        PARENT_URLS[id_string] = details.url;
    },
    {urls: ["<all_urls>"], types: ["main_frame", "sub_frame"]});



/* 
 * Because sending a POST for every GET request is inefficient, we want to batch our POSTS.
 * we want to batch our uploads.
 *
 * TODO: implement
 */
/*
window.setInterval(function(){
    // serialize batch
    batched_data = batch.join(";");
    
    if (batched_data){
        // clear batch
        batch = [];

        // send serialized batch off in a web request
        console.log("INFO: uploading batched data to server");
        httpPost(API_BASE_URL, batched_data);
    }

}, SECS_PER_SHIPMENT*1000);
*/
