/*
 *
 * This file (extension.js) implements all non-crypto functionality for the 
 * ScriptObservatory Chrome extension. 
 *
 * External code used is used to calculate SHA-256 hashes (sha256.js).
 *
 * This JavaScript code is loaded into the "background page" Chrome sets up 
 * for the extension. 
 *
 */


/* 
 * Constants
 */
PAGEVIEW_API_URL = "https://scriptobservatory.org/api/pageview";
SCRIPTCONTENT_API_URL = "https://scriptobservatory.org/api/scriptcontent";


/*
 * Global Data Structures
 * ----------------------
 * (1) SCRIPTS: Maps the tabId to a list of all scripts loaded for the given tab. 
 *              Cleared every time a request for a main_frame is made. Used and
 *              cleared every time the chrome.tabs.onUpdated listener fires and
 *              data is POSTed to the API.
 */
SCRIPTS = {};


/*
 * httpGet(url)
 * ------------
 * Perform a HTTP GET request to *url* and return its content
 */
function httpGet(url){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, false);
    xmlHttp.send();
    return xmlHttp.responseText;  // TODO: check return code
}


/*
 * httpPost(url, data)
 * -------------------
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
 * httpPut(url, data)
 * -------------------
 * Send json-ified *data* with a HTTP PUT request to *url*
 */
function httpPut(url, data){
    var request = new XMLHttpRequest();
    request.open("PUT", url, true);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(data));
    return;  // TODO: check return code
}


/* 
 * chrome.webRequest.onBeforeRequest listener
 * ------------------------------------------
 * We hook into chrome.webRequest.onBeforeRequest to keep track of the tabIds of
 * all requests for "main_frame" objects and to grab the content of requests for
 * "script" objects. 
 * 
 * For "script" requests, we perform our own download of the content and calculate
 * the sha256 hash of what we receive from the server. After the download of a 
 * "script" object is complete, if an entry is present in SCRIPTS for our current
 * tabId, we add the data we have (script URL & hash) to the SCRIPTS data structure.
 * 
 * It would be nice if we could let the browser do the request for "script" objects
 * normally and grab the content of the response it receives, but this is not
 * currently possible with the APIs chrome exposes to extensions. We're stuck 
 * injecting in this non-optimal way for now.
 * 
 * This functionality is discussed in the following issue: 
 *   https://code.google.com/p/chromium/issues/detail?id=104058
 * 
 * A draft proposal for adding this functionality is here: 
 *   https://groups.google.com/a/chromium.org/forum/#!msg/apps-dev/v176iCmRgSs/iM-72Evf8JgJ
 *
 * More general information is available in the chrome.webRequest docs: 
 *   https://developer.chrome.com/extensions/webRequest
 */
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        var tabId = details.tabId;
        var data = "";
        var hash = "";

        if (details.type == "script") {
            data = httpGet(details.url);
            hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);

            if (tabId in SCRIPTS) {
                SCRIPTS[tabId].push({"url": details.url, "hash": hash});
            }
            else {
                // TODO: look into auto-reporting this error
                console.log("tabId of " + tabId + 
                            " found for " + details.url +
                            " but main_frame not found!!");
            }
            
            var put_data = {"sha256": hash, 
                             "content": data};
            
            httpPut(SCRIPTCONTENT_API_URL + "/" + hash, put_data);      
      
            var data_uri = window.btoa(unescape(encodeURIComponent(data)));
            return {"redirectUrl":"data:text/html;base64, " + data_uri};
        }
        else if (details.type == "main_frame") {
            SCRIPTS[tabId] = []; 
            return {cancel: false}; 
        }        

        // TODO: look into auto-reporting this error...
        console.log("failed to hit a return statement!!");
    }, 
    {urls: ["<all_urls>"], types: ["script", "main_frame"]}, 
    ["blocking"]
);


/*
 * chrome.tabs.onUpdated listener
 * ------------------------------
 * We hook into chrome.tabs.onUpdated to determine when a page load has completed. 
 *
 * We check changeInfo.status to make sure that the reason the onUpdated listener
 * was called is that the status was changed to "complete". If this is so, we 
 * inject javascript to scrape all inline script tags out of the document body.
 * We then grab those script bodies and calculate the SHA-256 hash of each of
 * them. Once we have this, we add these inline scripts to the scripts already
 * collected and send a POST request to the PAGEVIEW_API_URL with the browsing data 
 * from SCRIPTS. We then delete tabId's entry from SCRIPTS.
 */
chrome.tabs.onUpdated.addListener(
    function(tabId, changeInfo, tab){
        if (changeInfo.status == "complete"){
            inline_callback = function(scripts){
                if (Object.prototype.toString.call( scripts ) == '[object Undefined]') return;
                scripts = scripts[0];

                var arrayLength = scripts.length;
                for (var i = 0; i < arrayLength; i++) {
                    data = String(scripts[i]);
                    hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);
                    var url = "inline_script_" + hash.slice(0,18);
                    SCRIPTS[tabId].push({"url": url, "hash": hash});
                }

                var timeStamp = new Date().getTime();
                var post_data = {"url": tab.url, 
                                 "date": timeStamp,
                                 "scripts": SCRIPTS[tabId]};

                delete SCRIPTS[tabId];

                console.log("finished ->" + JSON.stringify(post_data));
                httpPost(PAGEVIEW_API_URL, post_data);

            };

            injected_code = "var to_return = []; var scripts = " +
                    "document.getElementsByTagName('script'); for (var i=0; " +
                    "i<scripts.length; i++) { if(!scripts[i].src) to_return.push( " +
                    "scripts[i].innerHTML ); }; to_return";

            chrome.tabs.executeScript(tabId, 
                                      {code: injected_code},
                                      inline_callback);
           
        }
    }
);

