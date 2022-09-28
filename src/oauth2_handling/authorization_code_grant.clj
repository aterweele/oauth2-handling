(ns oauth2-handling.authorization-code-grant
  (:require [clojure.string :as str]
            crypto.random)
  (:import (java.net URI URLEncoder)
           (java.util Base64)))

(defn- encode [^String s]
  (URLEncoder/encode s "US-ASCII"))

(defn- encode-params [params]
  (str/join \& (map (fn [[k v]] (str (encode k) \= (encode v))) params)))

(defn- query
  "Add query parameters to `uri`. The query parameters will be encoded
  per <https://www.rfc-editor.org/rfc/rfc6749#appendix-B>."
  [uri query-params]
  ;; impl note: currently uri is a string, but this fn could be a
  ;; protocol function with impls for `java.net.URI`,
  ;; <https://github.com/lambdaisland/uri>, etc.
  (str uri \? (encode-params query-params)))

(defn authorization-request-uri
  "Construct the authorization request URI per
  <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1>."
  [{:keys [authorization-uri client-id base-redirect-uri]}
   & {:keys [scopes csrf-state]}]
  (query authorization-uri
         (cond-> {"response_type" "code", "client_id" client-id}
           base-redirect-uri (assoc "redirect_uri" base-redirect-uri)
           (seq scopes) (assoc "scope" (str/join \space scopes))
           csrf-state (assoc "state" csrf-state))))

(defn wrap-oauth
  "A Ring middleware that requires the request's `:session` to contain
  an `::access-token`, redirecting to an authorization code grant if
  it does not.

  Requires `ring.middleware.session/wrap-session`."
  [handler oauth-config
   & {:keys [scopes generate-state]
      :or {generate-state (partial crypto.random/url-part 32)}}]
  (fn [{:as request, :keys [uri session] {::keys [access-token]} :session}]
    (if access-token
      (handler request)
      (let [state (generate-state)]
        {:status 302
         :headers {"Location" (authorization-request-uri oauth-config
                                                         :scopes scopes
                                                         :csrf-state state)}
         :session (assoc-in session [::states state] uri)}))))

(defn access-token-request
  "An HTTP request to trade the `code` for an access token as per
  <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3>."
  [{:keys [access-token-uri client-id client-secret base-redirect-uri]}
   code
   & {:keys []}]
  ;; this an attempt to be HTTP client agnostic. Take this and give it
  ;; to the oauth-config's execute-request function.
  (let [request
        {:request-method :post
         :url access-token-uri
         :body (encode-params
                (merge {"grant_type" "authorization_code"
                        "code" code
                        "redirect_uri" base-redirect-uri}
                       (when-not client-secret
                         ;; <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3> "REQUIRED,
                         ;; if the client is not authenticating with
                         ;; the authorization server as described in
                         ;; Section 3.2.1."
                         {"client_id" client-id})))
         :headers (merge
                   ;; <https://www.rfc-editor.org/rfc/rfc6749#section-2.3>. Although
                   ;; the standard suggests that other ways of authenticating
                   ;; the client are possible, supporting HTTP basic
                   ;; authentication
                   ;; (<https://www.rfc-editor.org/rfc/rfc2617>) is
                   ;; required.
                   (when client-secret
                     {"Authorization"
                      (as-> (format "%s:%s" client-id client-secret) %
                        (.getBytes % "UTF-8")
                        (.encodeToString (Base64/getEncoder) %)
                        (str "Basic " %))})
                   {"Content-Type" "application/x-www-form-urlencoded"}
                   ;; FIXME GitHub requires this, or else the response
                   ;; will be application/x-www-form-urlencoded.
                   {"Accept" "application/json"})}]
    ;; FIXME for debugging
    (def _request request)
    request))

(defn authorization-response-handler
  "Make a Ring handler to handle the authorization response from the
  authorization server. Install the handler under e.g. GET /login.

  Requires `ring.middleware.params/wrap-params` and
  `ring.middleware.session/wrap-session`."
  [{:as oauth-config :keys [client-id base-redirect-uri execute-request]}]
  (fn [{:as request
        {:as session ::keys [states]} :session
        {:strs [error state code]} :query-params}]
    ;; it's possible that I may want to use
    ;; `ring.middleware.params/assoc-query-params` myself so that I
    ;; can specify the encoding.
    (prn "session" session)
    (prn "state" state)
    (if error
      ;; <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1>
      {:status 400}                 ; TODO improve
      (if-let [next (get states state)]
        {:status 302
         :headers {"Location" next}
         ;; FIXME: putting the access token etc in the session is
         ;; opinionated.
         :session
         (let [{{access-token "access_token", refresh-token "refresh_token"} :body}
               ;; <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>. TODO
               ;; this needs to be documented somehow. Make executing an
               ;; access token request first class?
               (execute-request
                (access-token-request oauth-config code))]
           (-> session
               (update ::states #(dissoc % state))
               (merge #::{:access-token access-token
                          :refresh-token refresh-token})))}
        {:status 400}))))
