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

already_seen = [];

app.controller("AppCtrl", function($http, $scope){
    var app = this;

    $scope.submitParentQuery = function(){
        var query = $scope.parentQueryText;
        var query_string = "";

        if (query != "") {
            queryString = "?q={\"filters\":[{\"name\":\"url\",\"op\":\"eq\",\"val\":\"%" + query + "%\"}]}";
        }

        $scope.populateData(queryString);
        show_website();
    }

    $scope.populateData = function(queryString){
        $http.get("/api/pageview" + queryString).success(function (data){
            app.records = data.objects;
               
            app.sites = [];
            seen_urls = [];
            for (var i = 0; i < app.records.length; i++){
                var cur_record = app.records[i];

                // TEMPORARY
                if (already_seen.contains(cur_record.url)) continue;
                already_seen.push(cur_record.url);
                // end TEMPORARY

                var to_add = {"url": cur_record.url,
                              "occur": 0,
                              "scripts": {}};
                
                for (var j = i; j < app.records.length; j++){
                    if (app.records[j].url == to_add.url){
                        to_add.occur += 1;
    
                        for (var script_ind = 0; script_ind < app.records[j].scripts.length; script_ind++){
                            var script_url = app.records[j].scripts[script_ind].url;
                            var script_hash = app.records[j].scripts[script_ind].hash;

                            if (!(script_url in to_add.scripts)){
                                to_add.scripts[script_url] = {};
                                to_add.scripts[script_url].url = script_url; // might not be necessary
                                to_add.scripts[script_url].hashes = {};
                                to_add.scripts[script_url].occur = 0;
                            }
                            
                            if (!(script_hash in to_add.scripts[script_url].hashes)){
                                to_add.scripts[script_url].hashes[script_hash] = {};
                                to_add.scripts[script_url].hashes[script_hash].hash = script_hash; // might not be necessary
                                to_add.scripts[script_url].hashes[script_hash].occur = 0;
                            }
                            
                            to_add.scripts[script_url].occur += 1;
                            to_add.scripts[script_url].hashes[script_hash].occur += 1;
                        }
                    }
                }

                // convert hash occur values to percentages
                for (var script_url in to_add.scripts){
                    for (var hash_val in to_add.scripts[script_url].hashes){
                        to_add.scripts[script_url].hashes[hash_val].occur *= (100.0 / to_add.scripts[script_url].occur);
                    }
                    
                    to_add.scripts[script_url].occur *= (100.0 / to_add.occur);
                }

                app.sites.push(to_add);
            }
            
        });
    }
});


