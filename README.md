# xao_cms
very flexible golang cms, that just fetch remote data and draw html using golang templates.

good if you using some rest cms ( like directus, strapi, hasura ) and need just flexible renderer

support:
[x] routing (with parameters) from config
[x] fetch http GET/POST, headers
[x] image processing (from source to dest). if file exists - skip... using for thumbnails etc. saving format - webp. library - chai2010/webp
[x] environments from config
[x] markdown using goldmark. with tables and emoji.
[x] bluemonday sanitize function
[x] sprig v3 functions
[x] pass GET reqest params to template env

now - production ready, but if next releases some functions / libraries can be changed.
