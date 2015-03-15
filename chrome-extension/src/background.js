/*
 *  Primary source code for ScriptWatcher extension.
 * 
 */
API_BASE_URL = "http://127.0.0.1:8080/api/script";


/*
 * httpGet(url) - Perform a HTTP GET request to *url* and return its content
 *
 */
function httpGet(url){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, false);
    xmlHttp.send();
    return xmlHttp.responseText;  // TODO: check return code
}


/*
 * httpPost(url, data) - Send json-ified *data* with a HTTP POST request to *url*
 *
 */
function httpPost(url, data){
    var request = new XMLHttpRequest();
    request.open("POST", url, true);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(data));
    return;  // TODO: check return code
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
 *
 */
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        // download script in a separate web request
        data = httpGet(details.url);

        // calculate SHA256 of script data   
        hash = CryptoJS.SHA256(data); 
        hash = hash.toString(CryptoJS.enc.Base64);

        // TODO batch URL & SHA256 to be sent off to server
        //info = details.url + " " + hash;
        //batch.push(info);

        var date = (new Date()).getTime();
        
        post_data = {"url": details.url, "sha256": hash, "req_type": details.type, "date": date};
        // for now we immediately send it:
        httpPost(API_BASE_URL, post_data);

        // convert to base64 and return the script code as a data URI
        data = window.btoa(data);
        
        console.log(info);
        return {"redirectUrl":"data:text/html;base64, " + data};
    }, 
    {urls: ["<all_urls>"], types: ["script", "object", "other"]}, 
    ["blocking"]
);


/* 
 * Because sending a POST for every GET request is inefficient, we want to batch our POSTS.
 * we want to batch our uploads.
 *
 * TODO: implement
 *
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
