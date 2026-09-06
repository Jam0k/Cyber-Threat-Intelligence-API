#!/usr/bin/env bash
# Build a feed from your stack, wire a webhook + alert rule, then poll for what is new.
# Researcher plan or above. Needs: curl, jq.
#   export TC_KEY=tc_live_…
#   bash stack_feed.sh https://hooks.example.com/threatcluster
set -euo pipefail
: "${TC_KEY:?set TC_KEY (mint one at https://threatcluster.io/settings#api)}"
HOOK_URL="${1:?webhook url (https, public host)}"
B=https://threatcluster.io/api/public/v1
H="X-API-Key: $TC_KEY"; J="Content-Type: application/json"
SINCE=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

echo "== feed from your stack (typed entities) =="
FEED=$(curl -sS -H "$H" -H "$J" -d '{"name":"Our stack","entities":[
  {"keyword":"FortiOS","entity_type":"platform"},{"keyword":"Okta","entity_type":"company"},
  {"keyword":"Ivanti","entity_type":"company"}]}' "$B/feeds" | jq -r .feed_id)
echo "feed $FEED"
curl -sS -H "$H" -H "$J" -d '{"keyword":"Snowflake","entity_type":"company"}' "$B/feeds/$FEED/entities" | jq -c '{added,count,limit}'

echo "== webhook =="
WH=$(curl -sS -H "$H" -H "$J" -d "{\"webhook_url\":\"$HOOK_URL\",\"name\":\"stack_feed.sh\"}" "$B/webhooks" | jq -r .webhook.id)
echo "webhook $WH"; curl -sS -X POST -H "$H" "$B/webhooks/$WH/test" | jq -c '{success,status_code}'

echo "== alert rule on the stack, delivered to the webhook =="
RULE=$(curl -sS -H "$H" -H "$J" -d "{\"name\":\"Stack vendors\",\"logic_operator\":\"OR\",\"webhook_id\":$WH,\"notify_webhook\":true,
  \"conditions\":[{\"entity_type\":\"platform\",\"entity_value\":\"FortiOS\"},{\"entity_type\":\"company\",\"entity_value\":\"Okta\"}]}" \
  "$B/alert-rules" | jq -r .rule.uuid)
echo "rule $RULE"
curl -sS -X POST -H "$H" "$B/alert-rules/$RULE/test" | jq -c '{total_matches, first: .matching_clusters[0].title}'

echo "== what is new in the feed since $SINCE =="
curl -sS -H "$H" "$B/feed?feed_type=custom&feed_id=$FEED&sort_by=latest&since=$SINCE&limit=10" \
  | jq -r '.items[] | "\(.date_range_latest // .pub_date | .[0:10])\t\(.ai_title // .title)"'

echo "== what fired since $SINCE =="
curl -sS -H "$H" "$B/alerts?since=$SINCE&limit=10" | jq -c '{count}'
echo "(keep or clean up: DELETE $B/feeds/$FEED, /webhooks/$WH, /alert-rules/$RULE)"
