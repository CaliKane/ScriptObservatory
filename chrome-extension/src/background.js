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
API_BASE_URL = "https://scriptobservatory.org/api/pageview";
SCRIPT_OBJECTS_TABLE = [];
MAX_PAGES = 10;


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
        var data = "";
        var hash = "";
        var parent_url = "";

        var id_string = makeIdString(details.tabId, details.frameId);
        var parent_id_string = makeIdString(details.tabId, details.parentFrameId);

        console.log(details.url + " --> " + id_string + " " + parent_id_string);        

        if (details.type == "main_frame"){
            MAIN_FRAME_URLS[id_string] = details.url;  // id_string --> url
            MAIN_FRAME_URLS[parent_id_string] = details.url;  // id_string --> url
        
            SCRIPTS[details.url] = [];
        }
        else {
            PARENTS[id_string] = parent_id_string;  // sub_frame id_string --> parent's id_string
        }

        while (id_string in PARENTS){
            id_string = PARENTS[id_string];
        }

        // debug:
        if (!(id_string in MAIN_FRAME_URLS)){
            console.log("root id_string of " + id_string + " found for " + details.url + " but main_frame not found!!");
        }
        root_url = MAIN_FRAME_URLS[id_string];

        if (details.type == "script"){
            data = httpGet(details.url);
            hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);
            SCRIPTS[root_url].push({"url": details.url, "hash": hash});
        }
 

        // we want to redirect to the data we received if the object is a script,
        // otherwise just be done and let the browser make its own request
        if (details.type == "script") {
            return {"redirectUrl":"data:text/html;base64, " + window.btoa(data)};
        }
        else {
            return {cancel: false};
        }

    }, 
    {urls: ["<all_urls>"], types: ["script", "main_frame", "sub_frame"]}, 
    ["blocking"]
);

chrome.tabs.onUpdated.addListener(
    function(tabId, changeInfo, tab){

        if (changeInfo.status == "complete"){
            
            var timeStamp = new Date().getTime();
            var post_data = {"url": tab.url, 
                             "date": timeStamp,
                             "scripts": SCRIPTS[tab.url]};
            
            delete SCRIPTS[tab.url];

            console.log("finished ->" + JSON.stringify(post_data));
            httpPost(API_BASE_URL, post_data);
        }
    }
);



/*
 * The current use of PARENT_URLS is an ugly hack to try to keep track of the URL of 
 * each page that could possibly spawn a javascript request later on.
 * 
 * Once the onBeforeRequest listener is expanded to grab all types of pages, the URLs
 * and parent/children relationships should be recorded there...
 * 
 * The current setup will fail in cases like news.ycombinator.com, where the initial
 * request actually returns a javascript object that then pulls down the page content.
 */

PARENT_URLS = {};
MAIN_FRAME_URLS = {};
PARENTS = {};
SCRIPTS = {};


