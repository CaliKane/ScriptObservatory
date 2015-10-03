function e(id) {
    return document.getElementById(id);
}

function truncate(str, maxLength) {
    str = str.trim()
    if(str.length > maxLength) {
        str = str.substring(0, maxLength + 1); 
        str += "...";
    }
    return str;
}

function get_color_from_hash(h){
    var color = "#" + h.substring(0,6);
    // temp hack to reduce the very light-colored colors chosed
    color = color.replace("f", "5");
    color = color.replace("e", "4");
    color = color.replace("d", "3");
    return color;
}

function arrayContains(arr, val, equals) {
    var i = arr.length;
    while (i--) {
        if ( equals(arr[i], val) ) {
            return true;
        }
    }
    return false;
}

function removeDuplicates(arr, equals) {
    var originalArr = arr.slice(0);
    var i, len, j, val;
    arr.length = 0;

    for (i = 0, len = originalArr.length; i < len; ++i) {
        val = originalArr[i];
        if (!arrayContains(arr, val, equals)) {
            arr.push(val);
        }
    }
}

function thingsEqual(thing1, thing2) {
    return thing1.hash === thing2.hash && thing1.url === thing2.url;
}

function printDetails(detailsList, clickable){
    var out = "";
    var i = detailsList.length;
    while (i--) {
        var truncated_url = truncate(detailsList[i].url, 75);
        var truncated_hash = detailsList[i].hash.substr(0,8);

        if (clickable){
            out += "<a href='https://scriptobservatory.org/explore.html?query=" + detailsList[i].url + "'>" + truncated_url + "</a> (";
            out += "<a href='https://scriptobservatory.org/explore.html?query=" + detailsList[i].hash + "'>" + truncated_hash + "</a>, ";
            out += "<a href='https://scriptobservatory.org/resource-content/" + detailsList[i].hash + "'>archived source</a>)";
        }
        else{
            out += truncated_url + " (" + truncated_hash + ")";
        }

        if (i > 0) out += "<br> ";
    }

    if (clickable){ 
        out += "<br><br><div align='right'>[<a href='#' onclick='view_locked=false; e(\"cur\").innerHTML = \"<br>\"'>unlock</a>]</div>"; 
    }

    return out;
}

function click(p) {
    view_locked = true;

    var dedup_details = p.details.slice(0);
    removeDuplicates(dedup_details, thingsEqual);

    e("cur").innerHTML = printDetails(dedup_details, true);
}

function mouseover(p) {
    if (!view_locked){
        var dedup_details = p.details.slice(0);
        removeDuplicates(dedup_details, thingsEqual);
        e("cur").innerHTML = printDetails(dedup_details, false);
    }
}

function mouseout(p) {
    if (!view_locked){
        var dedup_details = p.details.slice(0);
        removeDuplicates(dedup_details, thingsEqual);
        e("cur").innerHTML = printDetails(dedup_details, false);
    }
}

function getWidth() {
  if (self.innerHeight) {
    return self.innerWidth;
  }

  if (document.documentElement && document.documentElement.clientHeight) {
    return document.documentElement.clientWidth;
  }

  if (document.body) {
    return document.body.clientWidth;
  }
}

function initialize_data(resp_data){
    e("progress").style.display = "none";

    var first_t_in_days_ago = resp_data["first_t_in_days_ago"];
    var data = resp_data["json_data"];

    if (data.length == 0){
        e("info").innerHTML = "no scripts seen";
    }

    var margin = {top: 20, right: 20, bottom: 20, left: 20};
    var height_per_row = 15;
    
    var width = 900;
    var true_width = getWidth();
    if (true_width < 1200){
        width = true_width * 0.75;
    }

    var height = height_per_row*data.length + 45;
    var start_day = 0;
    var end_day = first_t_in_days_ago;

    var c = d3.scale.category20c();

    var NAME_OFFSET = 350;
    var x_label;
    var x = d3.scale.linear().range([0, width - NAME_OFFSET]);

    if (first_t_in_days_ago >= 3*30){
        x.domain([end_day/30, 0]);
        x_label = "months ago";
    }
    else if (first_t_in_days_ago > 3*7){ 
        x.domain([end_day/7, 0]);
        x_label = "weeks ago";
    }
    else if (first_t_in_days_ago == 0){
        x.domain([end_day, 0]);
        x_label = "(first seen today)";
    }
    else {
        x.domain([end_day, 0]);
        x_label = "days ago";
    }

    var formatDays = d3.format("d");
    var xAxis = d3.svg.axis().scale(x).orient("top").tickFormat(formatDays);

    var svg = d3.select("plot").append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
        .attr("font-family", "Courier, monospace")
        .style("background-color", "#F0F0F0")
        //.style("margin-left", margin.left + "px")
        .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var xScale = d3.scale.linear().domain([start_day, end_day]).range([NAME_OFFSET, width]);
    var g = svg.append("g").attr("class","resource");
    
    g.append("text")
        .attr("transform", "translate(" + ((width + NAME_OFFSET)/2) + ", 0)")
        .text(x_label);

    g.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(" + NAME_OFFSET + ", 30)")
        .call(xAxis)

    for (var j = 0; j < data.length; j++) {
        var g = svg.append("g").attr("class","resource");

        var circles = g.selectAll("circle")
            .data(data[j]['views'])
            .enter()
            .append("circle");

        var text = g.selectAll("text")
            .data(data[j]['views'])
            .enter()
            .append("text");

        circles
            .attr("cx", function(d, i) { return xScale(d['date']); })
            .attr("cy", 40 + j*height_per_row)
            .attr("r", function(d) { return 4.5 + d['n']/5.0; })
            .style("fill", function(d, i) { return get_color_from_hash(d['details'][0]['hash']); })
            .on("click", click)
            .on("mouseover", mouseover)
            .on("mouseout", mouseout);
        
        g.append("text")
            .attr("x", 0)
            .attr("y", 45 + j*height_per_row)
            .attr("class","label")
            .text(truncate(data[j]['name'], 37))
            .style("fill", function(d, i) { return j; })
    }
};

function get_data(hash){
    var xmlHttp = new XMLHttpRequest();
    
    xmlHttp.onreadystatechange = function() {
        if (xmlHttp.readyState == 4) {
            if (xmlHttp.status == 200) {
               var obj = JSON.parse(xmlHttp.responseText);
               initialize_data(obj); 
            }
        }
    };

    xmlHttp.open("GET", "https://scriptobservatory.org/webpage/" + hash + "/data");
    xmlHttp.send();
}   
