ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) to include _live content_ 
from the web in addition to certificate data. 

Initially, the only objects that the extension will target will be Javascript. 
If things go well, I'll probably try to extend the same idea to all objects 
that your browser pulls down off the internet.


Usage
-----

(check back later)


How It Works
------------

The ScriptObservatory extension is activated every time your browser is getting
ready to make a request for an object that Chrome has classified as a "script".
The extension will stop the browser from making a request to the server for the
script object and make its own request instead. Once it receives the content, it 
calculates a hash of the data it received and passes the object back to the browser
to be used as it normally would.

More documentation of specific design decisions can be found in the source code
itself (chrome-extension/background.js).

Periodically, the extension will upload its data to a server to be recorded. The 
data that's included in this is:
 1. The full URL of the object
 2. The parent URL of the page that embeds the object
 3. The SHA-256 hash of the retrieved content
 4. The time that you viewed the object

In the future, it might be extended to also support uploading the script itself
in the event that there's a hash mismatch between your extension and the hash
the server has on record for that URL.


Privacy
-------

With this extension installed and uploading enabled, your browser will send
the data described above to a remote server. If you don't feel comfortable with this, 
you can set it up to point to your own server instead.

Once I have more of it written, I'll come back to this tab and write more about 
what exactly someone could do with the data ScriptObservatory uploads.

At this point, ScriptObservatory doesn't play well with other extensions like adblockers.
You might find that your requests to Google Analytics & other trackers will go through
even though they would usually be blocked. I'll eventually try to address this, but it
isn't the highest priority at the moment.


Roadmap
-------

(check back later)


Contributing
------------

If you have ideas/comments/suggestions, go ahead and submit them as Issues or Pull Requests. Thanks!


