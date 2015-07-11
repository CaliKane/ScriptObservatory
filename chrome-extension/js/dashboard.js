/*
 * This contains all helper JS code for the dashboard menu
 */
var bp = chrome.extension.getBackgroundPage();

function e(id) {
    return document.getElementById(id);
}

function updateView(){
    filters = bp.getFilters();
    filter_html = ""

    for (var i = 0; i < filters.length; ++i){
        filter_html += (filters[i].toString() + ' <a href="#" id="remove-filter-' + i + '">remove</a> <br>\n');
    }
    e("current_filters").innerHTML = filter_html;

    // https://stackoverflow.com/questions/8909652/adding-click-event-listeners-in-loop
    for (var i = 0; i < filters.length; ++i){
        button = document.getElementById("remove-filter-"+i);
        if (typeof window.addEventListener === 'function'){
            (function (_button){
                button.addEventListener('click', function() { removeFilter(_button.id); });
            })(button);
        }
    }

    /* saved (reimplement later)
    if (bp.getReportingState()){
        e("current-reporting-status").innerHTML = "Reporting is ON";
    }
    else {
        e("current-reporting-status").innerHTML = "Reporting is OFF";
    }
    
    if (bp.getScriptContentReportingState()){
        e("current-sc-uploading-status").innerHTML = "Script Content Uploading is ON";
    }
    else{
        e("current-sc-uploading-status").innerHTML = "Script Content Uploading is OFF";
    }
    */
}

/*   
function toggleReportingStatus(){
    bp.toggleReportingState();
    updateView();
}

function toggleSCUploadingStatus(){
    bp.toggleScriptContentUploadingState();
    updateView();
}
*/

function removeFilter(filter){
    filter = filter.slice(14);  // remove "remove-filter-"
    bp.removeFilter(filter);
    updateView();
}

function submitNewFilter(){
    bp.addFilter(e("new_filter").value);
    updateView();
}

e("filterForm").addEventListener("submit", submitNewFilter);
updateView();

