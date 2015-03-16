var app = angular.module("app", []);

BASE_URL = "127.0.0.1:8080";


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


    /*
       Auto-refreshers for updates every 10s
        this is hacky and should be changed, but it's good enough for now...
    */
    window.setInterval(function(){
        $http.get("/api/script").success(function (data){
            if (data.objects != app.records){
                app.records = data.objects;
            }
        });
    }, 10000);


    /*
        Main Script API
    */
    $http.get("/api/script").success(function (data){
        // update raw data structure:
        app.records = data.objects;
        console.log("finished setting app.records");
           
        // build by_site data structure:
        //   TODO: needs major refactoring.....
        app.sites = [];
        
        seen_urls = [];
        for (var i = 0; i < app.records.length; i++){
            var cur_record = app.records[i];
        
            if (cur_record.parent_url == "n/a"){
                continue;
            }

            if (seen_urls.contains(cur_record.parent_url)){
                continue;
            }
    
            var to_add = {"url": cur_record.parent_url, "occur": 0, "scripts": {} };
            
            var active = false;
            for (var j = i; j < app.records.length; j++){
                if (app.records[j].parent_url == to_add.url){
                    /* this "active" variable is a hack and needs to be removed once page loads are tracked separately. */
                    if (active == false){
                        to_add.occur += 1;
                        active = true;   
                    }

                    if (!(app.records[j].url in to_add.scripts)){
                        to_add.scripts[app.records[j].url] = {};
                        to_add.scripts[app.records[j].url].url = app.records[j].url;
                        to_add.scripts[app.records[j].url].hashes = {}
                    }
                    
                    if (!(app.records[j].sha256 in to_add.scripts[app.records[j].url].hashes)){
                        to_add.scripts[app.records[j].url].hashes[app.records[j].sha256] = {}
                        to_add.scripts[app.records[j].url].hashes[app.records[j].sha256].occur = 0;
                        to_add.scripts[app.records[j].url].hashes[app.records[j].sha256].sha256 = app.records[j].sha256;
                    }
                    
                    to_add.scripts[app.records[j].url].hashes[app.records[j].sha256].occur += 1;
                }
                else{
                    active = false;
                }
            }

            // convert hash occur values to percentages
            for (var script_url in to_add.scripts){
                for (var hash_val in to_add.scripts[script_url].hashes){
                    to_add.scripts[script_url].hashes[hash_val].occur *= (100.0 / to_add.occur);
                }
            }


            seen_urls.push(cur_record.parent_url);
            app.sites.push(to_add);
        }
        console.log("finished setting app.sites");
    

        // build by_script data structure:

    });

});

