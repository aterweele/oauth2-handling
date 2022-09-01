(ns oauth2-handling.clj-http
  ;; TODO docstring. This ns should be for 2 things: using clj-http to
  ;; implement flows like the authorization code grant, and providing
  ;; clj-http middleware to enhance clj-http's OAuth2
  ;; support. clj-http has https://github.com/dakrone/clj-http#oauth2,
  ;; but it could support e.g. transparently using a refresh token.
  (:require [clj-http.client :as http]))

(defn execute-request
  "A function appropriate for the `:execute-request` of an
  oauth-config."
  [request]
  (http/request (assoc request :as :json-string-keys)))
