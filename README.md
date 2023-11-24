# TOAuth2

test for OAuth2 and get accessToken & idToken , now has 2 provider : google / facebook

you need public domain for test this, and must use https, so easiest and no cost way is raspberry pi as host and use cloudflare

and copy `.env_backup` to `.env` to run it, here only very simple code to get accessToken & idToken, and some doc you may need know, like this

https://auth0.com/blog/id-token-access-token-what-is-the-difference/

if you are doing sso providers, simply use idToken will be a good choice.
