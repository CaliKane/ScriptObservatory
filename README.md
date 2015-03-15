ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) to include **_live content_**
from the internet.

Initially, the only objects that the ScriptObservatory will target for analysis 
will be Javascript files. If things go well, I'll extend it to include all objects 
that your browser pulls down off the internet.


Usage
-----

(check back later)


How It Works
------------

The ScriptObservatory extension is notified every time your browser is about to
make a request for an object that Chrome classifies as a "script". ScriptObservatory
will stop the browser from making the request and make its own request instead.
Once it receives the content, it calculates a hash of the data it received and 
passes the object back to the browser to be used as it normally would.

This is not ideal, but documentation of specific design decisions can be found 
in the source code itself (start with chrome-extension/background.js).

Periodically, the extension will upload the data it collects to a server to be recorded. 
The information it collects includes:
 1. The full URL of the object
 2. The parent URL of the page that embeds the object
 3. The SHA-256 hash of the retrieved content
 4. The time that you viewed the object

In the future, ScriptObservatory might be extended to support uploading the content
received by the extension in the event that there's a hash mismatch between what you saw
and what the server has on record for that URL.

At this point, ScriptObservatory doesn't play well with other extensions like adblockers.
You might find that your requests to Google Analytics & other trackers will go through
even though they would usually be blocked. I'll eventually try to address this, but it
isn't the highest priority at the moment.


Privacy
-------

With this extension installed, your browser will send the data described above to a 
remote server. If you don't feel comfortable with this, you can set it up to point
to your own server instead.


Roadmap
-------

Near-term:
 - Add support to track parent URL
 - Support embedded script tags (ex: <script> ... </script>)
 - Support batching uploads
 - Expand Privacy documentation

Long-term:
 - Expand to collect data on _all_ web objects
 - Don't interfere with other extensions / ad-blockers
 - Add visualizations for server's data

Contributing
------------

If you have ideas/comments/suggestions, go ahead and submit them as Issues or Pull Requests. Thanks!


