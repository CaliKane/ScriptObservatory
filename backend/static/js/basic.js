function show_about(){
    document.getElementById('about_section').style.display="block";
    document.getElementById('raw_section').style.display="none";
    document.getElementById('website_section').style.display="none";
}

function show_raw(){    
    document.getElementById('about_section').style.display="none";
    document.getElementById('raw_section').style.display="block";
    document.getElementById('website_section').style.display="none";
}

function show_website(){    
    document.getElementById('about_section').style.display="none";
    document.getElementById('raw_section').style.display="none";
    document.getElementById('website_section').style.display="block";
}

String.prototype.repeat = function( num )
{
    return new Array( num + 1 ).join( this );
}

