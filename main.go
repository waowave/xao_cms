package main

/*

Author: Alexey Orlov. ao-xaocms@xao.io
your SHOULD save information about me.

*/

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	"image/draw"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"sync"

	"github.com/Masterminds/sprig/v3"
	"github.com/chai2010/webp"
	"github.com/disintegration/imaging"

	"github.com/gin-gonic/gin"
	"github.com/yuin/goldmark"
	emoji "github.com/yuin/goldmark-emoji"
	goldmark_extension "github.com/yuin/goldmark/extension"
	goldmark_html "github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v2"

	"github.com/golang-jwt/jwt/v4"
	"github.com/microcosm-cc/bluemonday"
)

var dump_rest bool

var yaml_router yamlRouterStruct
var fetch_always []string

var template_func_map template.FuncMap

func readYaml(filename string, out interface{}) error {
	yamlFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	file_bytes, _ := ioutil.ReadAll(yamlFile)

	if err := yaml.Unmarshal(file_bytes, out); err != nil {
		return err
	}

	return nil
}

type FetchesRow struct {
	URL                  string   `yaml:"url"`
	Method               string   `yaml:"method"`
	Important            bool     `yaml:"important"`
	FetchAlways          bool     `yaml:"fetch_always"`
	Request              string   `yaml:"request"`
	Headers              []string `yaml:"headers"`
	Timeout              uint     `yaml:"timeout"`
	RequestTemplate      *template.Template
	URLTemplate          *template.Template
	FetchHeadersTemplate *template.Template
}

type yamlRoutersRow struct {
	AuthRequired    bool                   `yaml:"auth_required"`
	Template        string                 `yaml:"template"`
	Fetch           []string               `yaml:"fetch"`
	Env             map[string]interface{} //looks as .local in template
	Headers         map[string]string      `yaml:"headers"`
	headersTemplate *template.Template
}

func (p *yamlRoutersRow) init() {
	if len(p.Headers) == 0 {
		p.headersTemplate = nil
		return
	}
	var header_txt bytes.Buffer
	for header_k, header_v := range p.Headers {
		header_txt.WriteString(header_k)
		header_txt.WriteString(": ")
		header_txt.WriteString(header_v)
		header_txt.WriteString("\n")
	}
	p.headersTemplate = fetchTemplateForString(header_txt.String())
}

/*
func (p *yamlRoutersRow) getHeadersTemplates() *template.Template {
	return p.headersTemplate
}
*/

type yamlRouterStruct struct {
	Routers      map[string]yamlRoutersRow    `yaml:"routers"`
	Fetches      map[string]FetchesRow        `yaml:"fetches"`
	FetchHeaders map[string]map[string]string `yaml:"fetch_headers"`
	Env          map[interface{}]interface{}  `yaml:"env"`
	StaticPaths  map[string]string            `yaml:"static"`
	JWT          JWTParameters                `yaml:"jwt"`
}

func fetchTemplateForString(val string) *template.Template {
	t, err := template.New("").Funcs(sprig.FuncMap()).Parse(val)
	if err != nil {
		fmt.Printf("error in template='%s'\n", val)
		panic(err)
	}
	return t
}

var bluemonday_policy *bluemonday.Policy

func func_sanitize(source string) template.HTML {
	return template.HTML(template.HTML(bluemonday_policy.Sanitize(source)))
}

func func_markdown(source string) template.HTML {
	var buf bytes.Buffer

	if err := markdown_glob.Convert([]byte(source), &buf); err != nil {
		panic(err)
	}
	return template.HTML(buf.String())
}

func func_html2string(source template.HTML) string {
	return string(source)
}

func func_byte2string(in []byte) string {
	return string(in)
}

func func_str2js(in string) template.JS {
	return template.JS(in)
}
func func_str2html(in string) template.HTML {
	return template.HTML(in)
}
func func_str2attr(in string) template.HTMLAttr {
	return template.HTMLAttr(in)
}
func func_str2css(in string) template.CSS {
	return template.CSS(in)
}
func func_str2url(in string) template.URL {
	return template.URL(in)
}

var fetch_cache = make(map[string]interface{})
var fetch_cache_mutex = sync.RWMutex{}

func executeTemplateForFetch(
	tpl *template.Template,
	server_var map[string]interface{},
	env map[interface{}]interface{},
) (bytes.Buffer, error) {
	request_writer := bytes.Buffer{}

	env_for_execute_in_template := make(map[string]interface{})
	env_for_execute_in_template["server"] = server_var
	env_for_execute_in_template["env"] = env

	err := tpl.Execute(&request_writer, env_for_execute_in_template)
	if err != nil {
		fmt.Printf("err=%v\n", err)
		return request_writer, err
	}
	return request_writer, nil

}

func gin_context_to_server_var(c *gin.Context) map[string]interface{} {
	get_params_str_map := make(map[string]string)

	for _, pv := range c.Params {
		get_params_str_map[pv.Key] = pv.Value
	}

	server_str_map := make(map[string]interface{})
	server_str_map["get"] = get_params_str_map

	headers_params_str_map := make(map[string]string)

	for pk, pv := range c.Request.Header {
		if len(pv) > 0 {
			headers_params_str_map[pk] = pv[0]
		}
	}

	server_str_map["header"] = get_params_str_map
	return server_str_map
}

func fetchByName(c *gin.Context, fetch_name string, server_params map[string]interface{}) (interface{}, error) {
	fetch_obj, ok := yaml_router.Fetches[fetch_name]
	if !ok {
		return nil, errors.New("fetch not found : " + fetch_name)
	}

	var fetch_html_object interface{}

	var fetch_http_resp *http.Response
	var err error = nil

	executed_url_writer := bytes.Buffer{}

	if executed_url_writer, err = executeTemplateForFetch(fetch_obj.URLTemplate, server_params, yaml_router.Env); err != nil {
		return nil, err
	}

	get_url_str := executed_url_writer.String()

	var default_timeout_ms time.Duration = 5000

	if fetch_obj.Timeout > 0 {
		default_timeout_ms = time.Duration(fetch_obj.Timeout)
	}

	http_client := &http.Client{
		//Timeout: default_timeout_ms * time.Millisecond,
	}

	if fetch_obj.Method == "POST" || fetch_obj.Method == "GET" || fetch_obj.Method == "" {
		if dump_rest {
			fmt.Printf("FETCH (%s) url = %s\n", fetch_name, get_url_str)
		}

		fetch_method := fetch_obj.Method
		if fetch_method == "" {
			fetch_method = "GET"
		}
		var body_io_reader *bytes.Buffer = nil

		if fetch_obj.Method == "POST" {
			executed_request_writer := bytes.Buffer{}
			if executed_request_writer, err = executeTemplateForFetch(fetch_obj.RequestTemplate, server_params, yaml_router.Env); err != nil {
				return nil, err
			}

			body_io_reader = bytes.NewBuffer(executed_request_writer.Bytes())
		}

		var http_req *http.Request

		if body_io_reader != nil {
			http_req, err = http.NewRequest(fetch_method, get_url_str, body_io_reader)
		} else {
			http_req, err = http.NewRequest(fetch_method, get_url_str, nil)
		}

		if err != nil {
			panic(err)
		}

		//headers
		executed_headers_writer := bytes.Buffer{}

		if fetch_obj.FetchHeadersTemplate != nil {
			if executed_headers_writer, err = executeTemplateForFetch(fetch_obj.FetchHeadersTemplate, server_params, yaml_router.Env); err != nil {
				return nil, err
			}
		}

		for header_key, header_value := range raw_headers_to_kv_map(executed_headers_writer.String()) {
			http_req.Header.Set(header_key, header_value)
		}

		timeout_ctx, cancel := context.WithTimeout(context.Background(), default_timeout_ms*time.Millisecond)
		defer cancel()
		http_req = http_req.WithContext(timeout_ctx)

		fetch_http_resp, err = http_client.Do(http_req)
	}

	if err != nil && fetch_obj.Important {
		return nil, fmt.Errorf("can't fetch important fetch %s with error %v", fetch_name, err)
	}

	if dump_rest {
		fmt.Printf("FETCH (%s) responsecode = %d header=%v\n", fetch_name, fetch_http_resp.StatusCode, fetch_http_resp.Header)
	}

	var json_err error
	if dump_rest {
		response_data, err_l := ioutil.ReadAll(fetch_http_resp.Body)
		if err_l != nil {
			return nil, fmt.Errorf("can't fetch (%s) read erro=%v ", fetch_name, err_l)
		}
		response_data_str := string(response_data)
		fmt.Printf("FETCH (%s) response_text = %s\n", fetch_name, response_data_str)

		json_err = json.NewDecoder(strings.NewReader(response_data_str)).Decode(&fetch_html_object)

	} else {

		json_err = json.NewDecoder(fetch_http_resp.Body).Decode(&fetch_html_object)
	}

	if json_err != nil {
		return nil, fmt.Errorf("can't fetch (%s) json unmarshall error = %v ", fetch_name, json_err)
	}

	fetch_cache_mutex.Lock()
	fetch_cache[get_url_str] = fetch_html_object
	fetch_cache_mutex.Unlock()

	if dump_rest {
		fmt.Printf("FETCH (%s) response = %s\n", fetch_name, fetch_html_object)
	}

	return fetch_html_object, nil

}

func gin_context_to_auth_var(c *gin.Context) (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	auth := c.Request.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("no Authorization header provided")
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth {
		return nil, fmt.Errorf("could not find bearer token in Authorization header")
	}

	jwt_int, jwt_err := yaml_router.JWT.jwt_check(token)
	if jwt_err != nil {
		return nil, jwt_err
	}
	ret["jwt"] = jwt_int
	return ret, nil
}

func raw_headers_to_kv_map(executed_headers_writer string) map[string]string {
	ret := make(map[string]string)
	for _, header_line := range strings.Split(executed_headers_writer, "\n") {
		if len(header_line) > 0 {
			header_line_splitted := strings.Split(header_line, ": ")
			header_key := header_line_splitted[0]
			if len(header_line) > 2 {
				header_value := header_line[len(header_key)+2:]
				ret[header_key] = header_value
			}
		}
	}
	return ret
}

func pageFunction(c *gin.Context, router_name string) error {

	fetches := make(map[string]interface{})
	fetchesMutex := sync.RWMutex{}
	var show500error error = nil

	router_row := yaml_router.Routers[c.FullPath()]

	should_fetch := make(map[string]string)
	for _, v := range fetch_always {
		should_fetch[v] = v
	}

	for _, fetch_name := range router_row.Fetch {
		should_fetch[fetch_name] = fetch_name
	}

	server_str_map := gin_context_to_server_var(c)

	if router_row.AuthRequired {
		auth_obj, auth_err := gin_context_to_auth_var(c)
		if auth_err != nil {
			c.AbortWithError(401, auth_err)
			return nil
		}
		server_str_map["auth"] = auth_obj
	}

	var wg sync.WaitGroup
	for _, fetch_name := range should_fetch {
		wg.Add(1)
		go func(fetch_name_param string, mtx *sync.RWMutex, fetches_catch map[string]interface{}) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panic_txt := fmt.Sprintln(r)
						show500error = fmt.Errorf("recovered: panic for fetch %s = %s", fetch_name_param, panic_txt)
						fmt.Println("stacktrace from panic: \n" + string(debug.Stack()))
					}
				}()

				fetch_result, err := fetchByName(c, fetch_name_param, server_str_map)
				if err != nil {
					show500error = err
				} else {
					mtx.Lock()
					fetches_catch[fetch_name_param] = fetch_result
					mtx.Unlock()
				}
			}()
			wg.Done()
		}(fetch_name, &fetchesMutex, fetches)
	}

	wg.Wait()

	if show500error != nil {
		c.AbortWithError(500, show500error)
		return show500error
	}

	executed_headers_writer := bytes.Buffer{}
	var err error
	//gettings headers
	if router_row.headersTemplate != nil {

		if executed_headers_writer, err = executeTemplateForFetch(router_row.headersTemplate, server_str_map, yaml_router.Env); err != nil {
			return err
		}
		for header_key, header_value := range raw_headers_to_kv_map(executed_headers_writer.String()) {
			c.Header(header_key, header_value)
		}
	}

	tpl_vars := gin.H{
		"fe":     fetches,
		"local":  router_row.Env,
		"env":    yaml_router.Env,
		"server": server_str_map,
	}

	var error_iface interface{}
	func(vars_for_template gin.H) {
		defer func() {
			if r := recover(); r != nil {
				error_iface = r
			}
		}()
		c.HTML(http.StatusOK, router_row.Template, vars_for_template)
	}(tpl_vars)

	if error_iface != nil {
		return fmt.Errorf("recovered panic for c.HTML return %v", error_iface)
	}

	return nil
}

func loadRouterYaml() {
	yaml_router = yamlRouterStruct{}
	fetch_always = []string{}

	if err := readYaml("conf/router.yml", &yaml_router); err != nil {
		panic(err)
	}

	for router_i := range yaml_router.Routers {
		old_router := yaml_router.Routers[router_i]
		old_router.init()
		yaml_router.Routers[router_i] = old_router
	}

	for fetch_i := range yaml_router.Fetches {
		old_fetch := yaml_router.Fetches[fetch_i]
		old_fetch.RequestTemplate = fetchTemplateForString(old_fetch.Request)
		old_fetch.URLTemplate = fetchTemplateForString(old_fetch.URL)

		if old_fetch.Headers != nil {
			for _, fetch_head_name := range old_fetch.Headers {
				var header_txt bytes.Buffer
				for fetch_head_key, fetch_head_value := range yaml_router.FetchHeaders[fetch_head_name] {
					header_txt.WriteString(fetch_head_key)
					header_txt.WriteString(": ")
					header_txt.WriteString(fetch_head_value)
					header_txt.WriteString("\n")
				}
				old_fetch.FetchHeadersTemplate = fetchTemplateForString(header_txt.String())
			}
		} else {
			old_fetch.FetchHeadersTemplate = nil
		}

		yaml_router.Fetches[fetch_i] = old_fetch

		if old_fetch.FetchAlways {
			fetch_always = append(fetch_always, fetch_i)
		}
	}

	if (yaml_router.JWT != JWTParameters{}) {
		if err := yaml_router.JWT.parse(); err != nil {
			panic(err)
		}
	} else {
		yaml_router.JWT.exists = false
		fmt.Println("jwt not set")
	}

}

var markdown_glob goldmark.Markdown

func initMarkdown() {

	markdown_glob = goldmark.New(
		goldmark.WithRendererOptions(
			goldmark_html.WithXHTML(),
			goldmark_html.WithUnsafe(),
		),
		goldmark.WithExtensions(
			goldmark_extension.Table,
			goldmark_extension.Strikethrough,
			goldmark_extension.Footnote,
			goldmark_extension.Typographer,
			goldmark_extension.DefinitionList,
			emoji.Emoji,

			goldmark_extension.NewLinkify(
				goldmark_extension.WithLinkifyAllowedProtocols([][]byte{
					[]byte("http:"),
					[]byte("https:"),
					[]byte("mailto:"),
					[]byte("ftp:"),
				}),
			),
		),
	)

}

func initRouter() {

	router := gin.Default()
	router.SetFuncMap(template_func_map)
	router.LoadHTMLGlob("templates/www/*")

	for router_name := range yaml_router.Routers {
		func(router_name_catched string) {
			router.GET(router_name_catched, func(c *gin.Context) {
				defer func() {
					if r := recover(); r != nil {
						panic_txt := fmt.Sprintln(r)

						fmt.Println("Recovered: panic = ", panic_txt)
						fmt.Println("stacktrace from panic: \n" + string(debug.Stack()))
						/* broken pipe?
						c.JSON(500, struct {
							Error string
						}{
							panic_txt,
						})
						*/

					}
				}()
				err := pageFunction(c, router_name_catched)
				if err != nil {
					fmt.Printf("pageFunction for %s return %v\n", router_name_catched, err)
					//				c.AbortWithError(500, err)
				}
			})
		}(router_name)
	}

	for static_key, static_value := range yaml_router.StaticPaths {
		router.Static(static_key, static_value)
	}

	router.Run(":8080")
	//	router.RunTLS(":8080", "./testdata/server.pem", "./testdata/server.key")
}

func initBluemonday() {
	bluemonday_policy = bluemonday.UGCPolicy() //.NewPolicy()
}

func func_lines(in string) []string {
	return strings.Split(in, "\n")
}

func initFuncMap() {

	fmap := make(map[string]any)

	local_func_map := template.FuncMap{
		"markdown":    func_markdown,
		"sanitize":    func_sanitize,
		"html2string": func_html2string,
		"b2s":         func_byte2string,
		"byte2string": func_byte2string,
		"implode":     strings.Join,
		"explode":     strings.Split,
		"lines":       func_lines,
		"str2js":      func_str2js,
		"str2css":     func_str2css,
		"str2html":    func_str2html,
		"str2attr":    func_str2attr,
		"str2url":     func_str2url,
		"image":       func_image,
		"image_fit":   func_image_fit,
	}

	for fk, fv := range sprig.FuncMap() {
		fmap[fk] = fv
	}

	for fk, fv := range local_func_map {
		fmap[fk] = fv
	}

	template_func_map = fmap

}

func if_env_true(env_name string) bool {
	fmt.Printf("getting env %s is ", env_name)
	env_r := os.Getenv(env_name)
	if env_r == "True" || env_r == "true" || env_r == "yes" || env_r == "YES" {
		fmt.Printf("true\n")
		return true
	} else {
		fmt.Printf("false\n")
		return false
	}

}

func initEnvAndParameters() {
	if if_env_true("DUMP_REST") || if_env_true("DUMP_FETCH") {
		dump_rest = true
	} else {
		dump_rest = false
	}
}

func initialize() {
	initEnvAndParameters()
	loadRouterYaml()
	initFuncMap()
	initBluemonday()
	initMarkdown()
	initRouter()

}

func main() {
	initialize()
}

type TemplateImage struct {
	img *image.NRGBA
}

func (ths *TemplateImage) Init(source string) error {
	src, err := imaging.Open(source)
	if err != nil {
		return fmt.Errorf("image init error: %s", err)
	}

	if img, ok := src.(*image.NRGBA); ok {
		ths.img = img
	} else {
		b := src.Bounds()
		m := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
		draw.Draw(m, m.Bounds(), src, b.Min, draw.Src)
		ths.img = m
	}
	return nil

}

func (ths *TemplateImage) Fit(width int, height int) *TemplateImage {
	ths.img = imaging.Fit(ths.img, width, height, imaging.Lanczos)
	return ths
}

func (ths *TemplateImage) Blur(bv float64) *TemplateImage {
	ths.img = imaging.Blur(ths.img, bv)
	return ths
}

func (ths *TemplateImage) Sharpen(bv float64) *TemplateImage {
	ths.img = imaging.Sharpen(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustGamma(bv float64) *TemplateImage {
	ths.img = imaging.AdjustGamma(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustContrast(bv float64) *TemplateImage {
	ths.img = imaging.AdjustContrast(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustBrightness(bv float64) *TemplateImage {
	ths.img = imaging.AdjustBrightness(ths.img, bv)
	return ths
}

func (ths *TemplateImage) AdjustSaturation(bv float64) *TemplateImage {
	ths.img = imaging.AdjustSaturation(ths.img, bv)
	return ths
}

func (ths *TemplateImage) Save(dest string, quality int) error {

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("image save error: %s", err)
	}
	defer f.Close()
	//Lossless: true,

	ext := strings.ToLower(filepath.Ext(dest))

	switch ext {
	case ".webp":
		{
			webp_opts := webp.Options{Quality: float32(quality)}

			if err := webp.Encode(f, ths.img, &webp_opts); err != nil {
				return fmt.Errorf("image save error: %s", err)
			}
			return nil
		}
	default:
		{
			err := imaging.Save(ths.img, dest, imaging.JPEGQuality(quality))
			if err != nil {
				return fmt.Errorf("image save error: %s", err)
			} else {
				return nil
			}

		}
	}

}

func func_image(source string) *TemplateImage {
	img := TemplateImage{}
	init_e := img.Init(source)
	if init_e != nil {
		return nil
	}
	return &img
}

func func_image_fit(source string, dest string, width int, height int, quality int) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	img := TemplateImage{}
	init_e := img.Init(source)
	if init_e != nil {
		return init_e
	}
	init_e = img.Fit(width, height).Save(dest, quality)
	return init_e
}

type JWTParameters struct {
	Method string `yaml:"method"`
	//	method jwt.SigningMethod
	Secret string `yaml:"secret"`
	secret interface{}
	exists bool
}

func (p *JWTParameters) getSecret() interface{} {
	return p.secret
}

func DecodeB64(message string) []byte {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	n, err := base64.StdEncoding.Decode(base64Text, []byte(message))
	if n == 0 || err != nil {
		return []byte{}
	}
	base64Text = base64Text[:n]
	return base64Text
}

func (p *JWTParameters) parse() error {
	b64data := DecodeB64(p.Secret)
	if len(b64data) == 0 {
		return fmt.Errorf("can't decode jwt secret base64 data")
	}
	p.secret = b64data
	p.exists = true
	return nil
}

func (jwt_params *JWTParameters) jwt_check(tokenString string) (interface{}, error) {

	if !jwt_params.exists {
		return nil, fmt.Errorf("JWT parameters not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		var ok bool
		switch jwt_params.Method {

		case "hmac":
			_, ok = token.Method.(*jwt.SigningMethodHMAC)
		case "rsa":
			_, ok = token.Method.(*jwt.SigningMethodRSA)
		case "ed25519":
			_, ok = token.Method.(*jwt.SigningMethodEd25519)
		case "ecdsa":
			_, ok = token.Method.(*jwt.SigningMethodECDSA)
		case "rsapps":
			_, ok = token.Method.(*jwt.SigningMethodRSAPSS)
		default:
			ok = false
		}

		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return jwt_params.getSecret(), nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		ret := make(map[string]interface{})
		ret["token"] = token
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			ret["claims"] = claims
		}
		return ret, nil
	} else {
		return nil, fmt.Errorf("token not valid")
	}

}
