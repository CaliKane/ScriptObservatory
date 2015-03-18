/*
 *
 *
 */


API_BASE_URL = "https://scriptobservatory.org";

var app = angular.module("app", []).filter('object2Array', function() {
    /* 
     * add object2Array filter to let us sort Objects from Angular in the 
     * same way we sort Arrays.
     */
    return function(input) {
      var out = []; 
      for(i in input){
        out.push(input[i]);
      }
      return out;
    }
  });


/* 
 * add a contains() method to Array objects, so we can check if 
 * element *k* exists in a given array.
 */
Array.prototype.contains = function(k) {
  for(var i=0; i < this.length; i++){
    if(this[i] === k){
      return true;
    }
  }
  return false;
}


app.controller("AppCtrl", function($http, $scope){
    var app = this;

    $scope.submitParentQuery = function(){
        var query = $scope.parentQueryText;
        var queryString = "{\"filters\": [{\"or\":[{\"name\":\"parent_url\",\"op\":\"like\",\"val\":\"%" + query + "%\"}, {\"name\":\"url\",\"op\":\"like\",\"val\":\"%" + query + "%\"}]}] }";
        $scope.populateData(queryString);
        by_parent();
    }

    $scope.submitScriptQuery = function(){
        var query = $scope.scriptQueryText;
        var queryString = "{\"filters\":[{\"name\":\"url\",\"op\":\"like\",\"val\":\"%" + query + "%\"}]}";
        $scope.populateData(queryString);
        by_url();
    }


    $scope.populateData = function(queryString){
        $http.get("/api/script?q=" + queryString).success(function (data){
            // update raw data structure:
            app.records = data.objects;
               
            // build by_site data structure:
            //   TODO: needs major refactoring.....
            app.sites = [];
            
            seen_urls = [];
            for (var i = 0; i < app.records.length; i++){
                var cur_record = app.records[i];

                if (seen_urls.contains(cur_record.parent_url) || seen_urls.contains(cur_record.url)){
                    continue;
                }
        
                var to_add = {"url": "",
                              "occur": 0,
                              "scripts": {}};
                
                if (cur_record.parent_url == "") {
                    to_add.url = cur_record.url;
                }
                else {
                    to_add.url = cur_record.parent_url;
                }

                for (var j = i; j < app.records.length; j++){
                    
                    if (app.records[j].parent_url == "" && app.records[j].url == to_add.url){
                        // if parent_url is null, this was not a script object! 
                        // if we end up in here, it's because we loaded the page itself!
                        to_add.occur += 1;
                    }

                    if (app.records[j].parent_url == to_add.url){
   
                        if (!(app.records[j].url in to_add.scripts)){
                            to_add.scripts[app.records[j].url] = {};
                            to_add.scripts[app.records[j].url].url = app.records[j].url;
                            to_add.scripts[app.records[j].url].hashes = {};
                            to_add.scripts[app.records[j].url].occur = 0;
                        }
                        
                        if (!(app.records[j].sha256 in to_add.scripts[app.records[j].url].hashes)){
                            to_add.scripts[app.records[j].url].hashes[app.records[j].sha256] = {};
                            to_add.scripts[app.records[j].url].hashes[app.records[j].sha256].occur = 0;
                            to_add.scripts[app.records[j].url].hashes[app.records[j].sha256].sha256 = app.records[j].sha256;
                        }
                        
                        to_add.scripts[app.records[j].url].occur += 1;
                        to_add.scripts[app.records[j].url].hashes[app.records[j].sha256].occur += 1;
                    }
                }

                // convert hash occur values to percentages
                for (var script_url in to_add.scripts){
                    for (var hash_val in to_add.scripts[script_url].hashes){
                        to_add.scripts[script_url].hashes[hash_val].occur *= (100.0 / to_add.scripts[script_url].occur);
                    }
                    
                    to_add.scripts[script_url].occur *= (100.0 / to_add.occur);
                }

                if (cur_record.parent_url == "") {
                    seen_urls.push(cur_record.url);
                }
                else {
                    seen_urls.push(cur_record.parent_url);
                }

                app.sites.push(to_add);
            }
        

            // build by_script data structure:
            //  ...TODO...
        });
    }
});


