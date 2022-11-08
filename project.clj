(defproject name.atw/oauth2-handling "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [crypto-random "1.2.1"]]
  :profiles {:dev {:source-paths ["dev-src"]
                   :dependencies [[ring "1.9.6"]
                                  [clj-http "3.12.3"]
                                  [cheshire "5.11.0"]]}}
  :deploy-repositories [["clojars" {:username "atw"
                                    :password :env/deploy_token}]
                        ["releases" :clojars]
                        ["snapshots" :clojars]])
