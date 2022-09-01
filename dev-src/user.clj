(ns user
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            oauth2-handling.authorization-code-grant
            oauth2-handling.clj-http
            ring.adapter.jetty
            (ring.middleware reload params))
  (:import java.io.PushbackReader))

(def server (atom nil))

(def oauth-config
  (-> "oauth-config.edn"
      io/resource
      io/reader
      PushbackReader.
      edn/read
      (assoc :execute-request oauth2-handling.clj-http/execute-request)))

(defn rudimentary-app
  [{:as request :keys [request-method uri]}]
  (if (and (= request-method :get) (= uri "/oauth"))
    
    ((oauth2-handling.authorization-code-grant/authorization-response-handler
      oauth-config)
     request)
    (do
      (println "could not handle request")
      (prn request)
      {:status 500})))

(defn start-server
  []
  (swap! server
         (constantly (ring.adapter.jetty/run-jetty
                      (-> rudimentary-app
                          ring.middleware.reload/wrap-reload
                          ring.middleware.params/wrap-params)
                      {:port 3000
                       :host "localhost"
                       :join? false}))))
