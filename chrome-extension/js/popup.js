/*
 * This contains all helper JS code for the popup menu
 */


BASE_QUERY_URL = "https://scriptobservatory.org/search/?query="


function jumpToAnalysisPage(){
    function redirectToActiveTabUrl(tabs){
        chrome.tabs.update(null, {url: BASE_QUERY_URL + encodeURIComponent(tabs[0].url)});
    };

    chrome.tabs.query({active: true, currentWindow: true}, redirectToActiveTabUrl);
};

function e(id) {
  return document.getElementById(id);
}

e("analyze-current-page").addEventListener("click", jumpToAnalysisPage);

