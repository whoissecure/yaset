package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"
)

type Template struct {
	Use          bool              `yaml:"use"`
	URL          string            `yaml:"url"`
	Headers      map[string]string `yaml:"headers"`
	Vars         map[string]string `yaml:"vars"`
	Verb         string            `yaml:"verb"`
	Data         map[string]string `yaml:"data"`
	Parse        string            `yaml:"parse"`
	AppendDomain bool              `yaml:"appendDomain"`
	RegexUse     bool              `yaml:"regexUse"`
}

func loadTemplateFromFile(filename string, target string, cfg *ini.File) (use bool, url string, headers map[string]string, verb string, data map[string]string, parse string, append bool, regexUse bool) {
	readedFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return false, "File can not be readed", nil, "", nil, "", false, false
	}

	readedFile = []byte(strings.ReplaceAll(string(readedFile), "engine.target", target))
	template := Template{}
	err = yaml.Unmarshal(readedFile, &template)
	if err != nil {
		return false, "Error while unmarshaling the file", nil, "", nil, "", false, false
	}

	for key, value := range template.Vars {
		if strings.HasPrefix(value, "engine.config") {
			values := strings.Split(value, ".")
			if len(values) < 3 {
				continue
			}

			if cfg != nil {
				iniValue := cfg.Section(values[2]).Key(values[3]).String()
				if iniValue != "" {
					value = strings.ReplaceAll(value, value, iniValue)
				} else {
					return false, "Variable not found in config file", nil, "", nil, "", false, false
				}
			}
		}
		template.URL = strings.ReplaceAll(template.URL, ":"+key, value)
		for k, v := range template.Headers {
			template.Headers[k] = strings.ReplaceAll(v, ":"+key, value)
		}

		for k, v := range template.Data {
			template.Data[k] = strings.ReplaceAll(v, ":"+key, value)
		}
	}

	return template.Use, template.URL, template.Headers, template.Verb, template.Data, template.Parse, template.AppendDomain, template.RegexUse
}

func APIrequest(url string, headers map[string]string, method string, data map[string]string) ([]byte, *http.Response, error) {
	var reqBody io.Reader
	if len(data) > 0 {
		formData := make([]string, 0)
		for key, value := range data {
			formData = append(formData, key+"="+value)
		}

		formDataStr := strings.Join(formData, "&")
		reqBody = strings.NewReader(formDataStr)
	} else {
		reqBody = strings.NewReader("")
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, nil, err
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	if len(data) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return body, resp, nil
}

func checkDuplicated(enumerated_subdomains []string, value string) (result bool) {
	for _, item := range enumerated_subdomains {
		if item == value {
			return true
		}
	}
	return false
}

func allAPIsUsage(d string, cfg *ini.File) (enumerated_subdomains []string) {
	d = regexp.MustCompile(`^\*\.`).ReplaceAllString(strings.TrimSpace(d), "")
	escapedDomain := regexp.QuoteMeta(d)
	re := regexp.MustCompile(fmt.Sprintf(`\.%s$`, escapedDomain))
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	templatesPath := filepath.Join(homeDir, "yaset-templates")
	files, err := filepath.Glob(filepath.Join(templatesPath, "*.yaml"))
	if err != nil {
		fmt.Println(err)
		return
	}

	var wg sync.WaitGroup
	for _, file := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			use, url, headers, method, data, parse, appendDomain, regexUse := loadTemplateFromFile(f, d, cfg)

			if use {
				body, _, err := APIrequest(url, headers, method, data)
				if err != nil {
					fmt.Println("Error:", err)
					return
				}

				if parse != "" {
					tmpSubdomains := gjson.Get(string(body), parse).Array()
					if err != nil {
						fmt.Println("Error:", err)
						return
					}

					for _, value := range tmpSubdomains {
						val := value.String()
						if appendDomain {
							val = val + "." + d
						}

						if re.MatchString(val) && !strings.HasPrefix(val, "*") && !checkDuplicated(enumerated_subdomains, val) {
							enumerated_subdomains = append(enumerated_subdomains, val)
						}
					}
				} else if regexUse {
					r := regexp.MustCompile(fmt.Sprintf(`(?i)(%%(25)*2F){0,1}[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.%s`, escapedDomain))
					tmpSubdomains := r.FindAllStringSubmatch(string(body), -1)
					if err != nil {
						fmt.Println("Error:", err)
						return
					}

					for _, value := range tmpSubdomains {
						val := value[0]
						deleteRe := regexp.MustCompile(`(?i)(%(25)*2F){0,1}`)
						val = deleteRe.ReplaceAllString(val, "")

						if appendDomain {
							val = val + "." + d
						}

						if strings.HasPrefix(val, "%2F") || strings.HasPrefix(val, "%2f") {
							val = val[3:]
						}

						if re.MatchString(val) && !checkDuplicated(enumerated_subdomains, val) {
							enumerated_subdomains = append(enumerated_subdomains, val)
						}
					}
				}
			}

		}(file)
	}

	wg.Wait()
	return enumerated_subdomains
}

func bruteforceResolution(file string, d string) (resolvedSubdomains []string) {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return nil
	}

	var wg sync.WaitGroup

	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		modifiedLine := line + "." + d
		wg.Add(1)
		go func(modified string) {
			defer wg.Done()
			_, err := net.LookupHost(modified)
			if err == nil {
				resolvedSubdomains = append(resolvedSubdomains, modified)
			}
		}(modifiedLine)
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	wg.Wait()
	return resolvedSubdomains
}

func resolveAllDomains(enumerated_subdomains []string) (resolvedSubdomains []string) {
	var wg sync.WaitGroup

	for _, domain := range enumerated_subdomains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			_, err := net.LookupHost(d)
			if err == nil {
				resolvedSubdomains = append(resolvedSubdomains, d)
			}
		}(domain)
	}

	wg.Wait()
	return resolvedSubdomains
}

func main() {
	var homeDir string
	var err error

	homeDir, err = os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	d := flag.String("d", "", "The domain to be enumerated.")
	p := flag.Bool("p", false, "Passive mode to enumerate using APIs.")
	bruteforce := flag.String("w", "", "Wordlist to bruteforce domains.")
	resolve := flag.Bool("r", false, "Resolve all the domains.")
	write := flag.String("o", "", "File to write the results.")
	config := flag.String("config", homeDir+"/.config/yaset/config.ini", "Path to config file")
	check := flag.Bool("c", false, "Check templates status and errors.")

	flag.Parse()

	var cfg *ini.File

	if _, err = os.Stat(*config); os.IsNotExist(err) {
		cfg = ini.Empty()
	} else {
		cfg, err = ini.Load(*config)
		if err != nil {
			fmt.Printf("Fail to read file: %v", err)
			os.Exit(0)
		}
	}

	if *check {
		if _, err := os.Stat(*config); os.IsNotExist(err) {
			fmt.Println("Config file", *config, "does not exist.")
			os.Exit(0)
		}
		fmt.Println("[+] Checking the templates status with the config file:", *config)
		templatesPath := filepath.Join(homeDir, "yaset-templates")
		files, err := filepath.Glob(filepath.Join(templatesPath, "*.yaml"))
		if err != nil {
			fmt.Println(err)
			return
		}

		count := 0
		var wg sync.WaitGroup
		for _, file := range files {
			wg.Add(1)
			go func(f string) {
				defer wg.Done()
				use, url, _, method, _, parse, _, regexUse := loadTemplateFromFile(f, "example.com", cfg)
				if use {
					if !(strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")) {
						fmt.Println("[!] URL invalid in:", filepath.Base(f))
						return
					}

					if !(method == "GET" || method == "POST") {
						fmt.Println("[!] Method invalid in:", filepath.Base(f))
						return
					}

					if !(regexUse || parse != "") {
						fmt.Println("[!] No match used in:", filepath.Base(f))
						return
					}

					count = count + 1
				} else {
					if !(strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")) {
						fmt.Println("[!]", url, "for:", filepath.Base(f))
						return
					} else {
						fmt.Println("[!] Template disabled:", filepath.Base(f))
						return
					}
				}
			}(file)
		}
		wg.Wait()
		fmt.Println("[+] Found", count, "templates configured correctly.")
		os.Exit(0)
	}

	if *d == "" {
		fmt.Println("A domain is required.")
		fmt.Println("See usage with: ./yaset -h")
		os.Exit(0)
	}

	if !*p && *bruteforce == "" {
		fmt.Println("Choose between passive or bruteforce mode is required.")
		fmt.Println("See usage with: yaset -h")
		os.Exit(0)
	}

	enumerated_subdomains := []string{}
	if *p {
		enumerated_subdomains = allAPIsUsage(*d, cfg)
		if *resolve {
			enumerated_subdomains = resolveAllDomains(enumerated_subdomains)
		}
	}

	if *bruteforce != "" {
		bruteforcedSubdomains := bruteforceResolution(*bruteforce, *d)

		for k := range bruteforcedSubdomains {
			if !checkDuplicated(enumerated_subdomains, bruteforcedSubdomains[k]) {
				enumerated_subdomains = append(enumerated_subdomains, bruteforcedSubdomains[k])
			}
		}
	}

	if *write != "" {
		f, _ := os.OpenFile(*write, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		defer f.Close()
		dw := bufio.NewWriter(f)
		for _, k := range enumerated_subdomains {
			dw.WriteString(k + "\n")
			fmt.Println(k)
		}
		dw.Flush()
	} else {
		for _, k := range enumerated_subdomains {
			fmt.Println(k)
		}

	}
}
