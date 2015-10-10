ScriptObservatory [![Build Status](https://api.travis-ci.org/andy11/ScriptObservatory.svg?branch=master)](https://travis-ci.org/andy11/ScriptObservatory) 
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) by recording and organizing
information about the **_live content_** people are seeing on
the internet.

The long-term goal of the [website](https://www.scriptobservatory.org)
is for it to be a place where anyone can analyze the record of 
what people have been sent while on the internet. The 
long-term goal for the 
[Chrome extension](https://github.com/andy11/ScriptObservatory#usage)
is to crowdsource the data collection and to act as a 
**_content-aware_** resource blocker, letting you have finer control 
over what runs on your computer. 

Initially, the only objects that will be analyzed are JavaScript files 
and iframes. Eventually, it might be extended to include other types 
of content. 


Usage
-----

(Check back later for more information on how to use the Chrome extension. You can 
install it as [an unpacked extension](http://superuser.com/questions/247651/how-does-one-install-an-extension-for-chrome-browser-from-the-local-file-system)
at your own risk for now.)


How It Works
------------

The ScriptObservatory Chrome extension is notified every time your browser is 
about to make a request for an object that Chrome classifies as a "script" or "sub_frame". 
The extension stops the browser from making the request and makes its own request
instead. Once it receives the content, it calculates a hash of the data and 
passes the object back to the browser.

This way of grabbing the content isn't ideal, however documentation of design
decisions can be found directly in the source code. 
([chrome-extension/js/extension.js](https://github.com/andy11/ScriptObservatory/blob/master/chrome-extension/js/extension.js)
would be a good place to start.)


Privacy
-------

With the ScriptObservatory Chrome extension installed, your browser will send these
three pieces of information to the ScriptObservatory backend each time you view a webpage:
 1. The URL of the webpage
 2. The URL of each piece of JavaScript and each iframe included in the webpage
 3. The SHA-256 hash of the content of each script and iframe you observe

You can optionally have the Chrome extension send the content of the scripts you
observe. This will be turned off by default in all released versions.

Here are some steps that have been taken to make this process as trustworthy as possible:
 - The connection from you to the ScriptObservatory backend will always be 
   [encrypted using SSL/TLS](https://www.ssllabs.com/ssltest/analyze.html?d=scriptobservatory.org). 
 - Unless they're present in the URLs, no IP addresses or "User ID" values are ever recorded
   in the database. Your observations will be immediately mixed in with those of everyone else. 
   If you see an IP address or User ID value in a URL string, 
   [let me know](mailto:scriptobservatory@gmail.com) and I'll remove them and blacklist further 
   reports for that website. 
 - The source code for both the client and the server will always be available for you to 
   review. (See the [chrome-extension/](https://github.com/andy11/ScriptObservatory/tree/master/chrome-extension) 
   and [backend/](https://github.com/andy11/ScriptObservatory/tree/master/backend) 
   directories to get started.)
 - The exact time that's recorded when you report an observation will be 
   [binned into 12-hour bins](https://github.com/andy11/ScriptObservatory/issues/43) to discourage 
   someone from correlating similar requests as possibly coming from the same person.


Roadmap
-------

TODOs are tracked with [GitHub Issues](https://github.com/andy11/ScriptObservatory/issues).

If you have questions or want to get involved, you can see issues tagged as "help-wanted" 
[here](https://github.com/andy11/ScriptObservatory/labels/help%20wanted)
or [send me an email](mailto:scriptobservatory@gmail.com).


