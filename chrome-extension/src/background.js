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
 * ---------
 * (1) API_BASE_URL: The base URL for the Pageview API.
 */
API_BASE_URL = "https://scriptobservatory.org/api/pageview";


/*
 * GLOBAL DATA STRUCTURES
 * ----------------------
 * (1) SCRIPTS: Maps the tabId to a list of all scripts loaded for the given tab. Cleared every
 *              time a request for a main_frame is made. Used & deleted from memory every time 
 *              the chrome.tabs.onUpdated listener fires and data is POSTed to API.
 */
SCRIPTS = {};


/*
 * FUNCTION httpGet(url)
 * ---------------------
 * Perform a HTTP GET request to *url* and return its content
 */
function httpGet(url){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, false);
    xmlHttp.send();
    return xmlHttp.responseText;  // TODO: check return code
}


/*
 * FUNCTION httpPost(url, data)
 * ----------------------------
 * Send json-ified *data* with a HTTP POST request to *url*
 */
function httpPost(url, data){
    var request = new XMLHttpRequest();
    request.open("POST", url, true);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(data));
    return;  // TODO: check return code
}


/* 
 * FUNCTION added to chrome.webRequest.onBeforeRequest listeners
 * -------------------------------------------------------------
 * We hook into chrome.webRequest.onBeforeRequest to keep track of the tabIds of "main_frame"
 * requests and to grab the content of "script" requests. For "script" requests, we perform our 
 * own download of the content and calculate the sha256 hash of what we receive from the server.
 * After the download of a "script" object is complete, if an entry is present in SCRIPTS for 
 * our current tabId, we add the data we have (script URL & hash) to the SCRIPTS data structure.
 * 
 * It would be nice if we could let the browser do the request for "script" objects normally 
 * and grab the content of the response it receives, but this is not currently possible with 
 * the chrome APIs. We're stuck injecting in this non-optimal way for now.
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
        var tabId = details.tabId;

        console.log(details.url + " --> " + tabId);

        if (details.type == "main_frame"){
            SCRIPTS[tabId] = []; 
        }
        else if (details.type == "script"){
            data = httpGet(details.url);
            hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);

            if (tabId in SCRIPTS){
                SCRIPTS[tabId].push({"url": details.url, "hash": hash});
            }
            else{
                // TODO: determine why this happens and find a workaround
                console.log("tabId of " + tabId + " found for " + details.url + " but main_frame not found!!");
            }

            // TODO: determine why btoa call fails (encoding issues?)
            return {"redirectUrl":"data:text/html;base64, " + window.btoa(data)};
        }

        return {cancel: false};
    }, 
    {urls: ["<all_urls>"], types: ["script", "main_frame", "sub_frame"]}, 
    ["blocking"]
);


/*
 * FUNCTION added to chrome.tabs.onUpdated listeners
 * -------------------------------------------------
 * We hook into chrome.tabs.onUpdated to determine when a page load has completed. 
 *
 * We check changeInfo.status to make sure that the onUpdated listener has been called
 * because the status has been changed to "complete" and, if this is so, send a POST
 * request to the API_BASE_URL containing the browsing data collected and stored in 
 * the SCRIPTS data structure. We then delete tabId's entry from SCRIPTS.
 */
chrome.tabs.onUpdated.addListener(
    function(tabId, changeInfo, tab){
        if (changeInfo.status == "complete"){
            var timeStamp = new Date().getTime();
            var post_data = {"url": tab.url, 
                             "date": timeStamp,
                             "scripts": SCRIPTS[tabId]};
            
            delete SCRIPTS[tabId];

            console.log("finished ->" + JSON.stringify(post_data));
            httpPost(API_BASE_URL, post_data);
        }
    }
);

