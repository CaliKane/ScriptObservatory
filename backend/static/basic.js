function by_raw(){    
    document.getElementById('by_raw').style.display="block";
    document.getElementById('by_url').style.display="none";
    document.getElementById('by_parent').style.display="none";
}

function by_url(){    
    document.getElementById('by_raw').style.display="none";
    document.getElementById('by_url').style.display="block";
    document.getElementById('by_parent').style.display="none";
}

function by_parent(){    
    document.getElementById('by_raw').style.display="none";
    document.getElementById('by_url').style.display="none";
    document.getElementById('by_parent').style.display="block";
}
