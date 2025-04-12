# Introduction
Yaset (Yet Another Subdomain Enumeration Tool) is a subdomain enumeration tool which main function is the passive enumeration. The APIs used as sources in the passive enumeration are added creating templates in YAML, making Yaset a tool that can grow easily.

# Installation
To install the tool, you can execute:
```
go install github.com/whoissecure/yaset/cmd/yaset@latest
```

In addition, you need to clone the templates' repository, where you can add you own sources:
```
git clone https://github.com/whoissecure/yaset-templates $HOME
```

To configure the API keys, create the directory `$HOME/.config/yaset` and save a configuration file:
```
mkdir $HOME/.config/yaset
curl https://raw.githubusercontent.com/whoissecure/yaset/refs/heads/main/config.ini -o $HOME/.config/yaset/config.ini
```

# Modes
To execute Yaset, you must choose one mode or both. The passive mode interacts with third party APIs to obtain subdomains, and the bruteforce mode uses a wordlist to check if the formed domain resolves to an IP.

## Passive mode
This is the main mode of Yaset and to use it, you need to specify the `-p` flag. There are templates that need variables to be defined and for that, a ini file is used. An example for this file is in the repository and it is placed in `~/.config/yaset/config.ini`, the default path that will use the tool automatically. In this file, the main things defined will be the API keys, but it is possible to add variables if needed (this is better explained in the templates section). It is possible to check how many templates are loaded correctly and how many need the variables to be added to the ini file because there are variables missing executing Yaset with the `-c` argument.

## Bruteforce
To bruteforce subdomains, the argument `-w` with a wordlist. This mode combines each line of the text file with the domain to be bruteforced and tries to resolve it.

# Usage
```
Usage of yaset:
  -c	Check templates status and errors.
  -config string
    	Path to config file (default "~/.config/yaset/config.ini")
  -d string
    	The domain to be enumerated.
  -o string
    	File to write the results.
  -p	Passive mode to enumerate using APIs.
  -r	Resolve all the domains.
  -w string
    	Wordlist to bruteforce domains.
```

# Templates
The templates are stored in other repository (https://github.com/whoissecure/yaset-templates). To add APIs, templates with YAML are created. The format of the templates to define the HTTP requests is the following:

```yaml
name: yasetDB # Optional. Now, it is only a reference, the tool does not use it.
use: true # Optional. If it is not present or if it is in false, the template is not used.
url: http://yaset.local/subdomains/:target?limit=1000 # Obligatory. Example of URL. It can use GET parameters.
verb: POST # Obligatory. HTTP method.
headers: # Optional. You can add headers to the request.
  X-API-Key: :apikey
data: # Optional. Request body.
  domain: :target
  test: value
vars: # Variables to replace in URL, headers and request body. Target or equivalent is mandatory as engine.target to be replaced by the domain introduced as target.
  target: engine.target
  apikey: engine.config.service.key
# Choose between parse or regexUse to get the domains from the response body.
parse: "@this.#.host" # Parse the JSON from the response body (if it is in json format) with a GJSON (https://gjson.dev) expression.
regexUse: true # Use a regex to match all the domains in the response body.
```

First of all, when parsing a template, the tool replaces "engine.target" by the domain introduced to be enumerated and then, it replaces the variables with the format "engine.config.X.Y". 

The variables of type "engine.config" are used to get a value from the config.ini file. The default path for the config file is `~/.config/yaset/config.ini` and, for example, the variable defined as "engine.config.X.Z" in the template, should be defined in the ini file as:

```ini
[X]
Z = "API_KEY_OR_VAR_HERE"
```

The vars field make replacements in URL, headers and request body, and then Yaset forges the HTTP request to be done.

The parser used in the requests for the APIs with json format is GJSON (https://gjson.dev/). It is possible to parse other types of responses indicating in the template the use of the regex, instead of the gjson expression.

To check if the created template is valid for its syntax, you can place it in the `~/yaset-templates` directory and execute Yaset with the `-c` flag.

# Contributing
If you have any feature that you want to be added, please, open an issue or make a pull request.

# References
- Post written in spanish in my personal blog: https://www.whoissecure.xyz/2023/05/yaset.html

# To do
- [ ] Change the structure of the project to be used as a library or like cli tool
- [ ] Support multiple requests in one template (Used for example to obtain a token and use then before or to get a list of links and then visit and parse them)
- [ ] Support yaset-scripts too?
- [ ] Enumeration with other methods than APIs and brute force or maintain just passive enumeration?
- [ ] Support `engine.iterate` with variables like `start`, `end` and `max`, to make multiple requests changing a numeric parameter.
- [X] Some domains are taken as url encoded "%252FX.Z.Y" due to double URL encoding in the results of the APIs, fix it some way, maybe upgrading the regex (?
- [ ] Change parse in templates to engine.regex/gjson.expression/cookies.CookieName to use when supporting various reqs.
- [ ] Iterate over a list of variables to make the same request with different parameters (Example: in github api, search for C, HTML, CSS, etc in just one template)
- [ ] Possiblity to define step for range in templates instead of being always 1
- [X] Upgrade the regex to take other URL encoded chars
- [ ] Check if API domain resolves before make a HTTP request
- [ ] Add verbose mode to see things like APIs not working, templates not loaded, etc
