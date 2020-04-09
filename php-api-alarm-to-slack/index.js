/*
 * CloudWatch alarm notifications to Slack streaming function for AWS Lambda.
 * https://github.com/blueimp/aws-lambda
 *
 * Required environment variables:
 * - webhook:     AWS KMS encrypted Slack WebHook URL.
 *
 * Optional environment variables:
 * - channel:     Slack channel to send the messages to.
 * - username:    Bot username used for the slack messages.
 * - icon_emoji:  Bot icon emoji used for the slack messages.
 * - icon_url:    Bot icon url used for the slack messages.
 *
 * Copyright 2017, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * https://opensource.org/licenses/MIT
 */

'use strict'

const ENV = process.env
if (!ENV.webhook) throw new Error('Missing environment variable: webhook')

let webhook

const AWS = require('aws-sdk')
const url = require('url')
const https = require('https')

function handleResponse (response, callback) {
  const statusCode = response.statusCode
  console.log('Status code:', statusCode)
  let responseBody = ''
  response
    .on('data', chunk => {
      responseBody += chunk
    })
    .on('end', chunk => {
      console.log('Response:', responseBody)
      if (statusCode >= 200 && statusCode < 300) {
        callback(null, 'Request completed successfully.')
      } else {
        callback(new Error(`Request failed with status code ${statusCode}.`))
      }
    })
}

function post (requestURL, data, callback) {
  const body = JSON.stringify(data)
  const options = url.parse(requestURL)
  options.method = 'POST'
  options.headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body)
  }
  console.log('Request options:', JSON.stringify(options))
  console.log('Request body:', body)
  https
    .request(options, response => {
      handleResponse(response, callback)
    })
    .on('error', err => {
      callback(err)
    })
    .end(body)
}

function buildSlackMessage (data) {
  const currentDate = new Date()
  const endDate = currentDate.toISOString().replace(/\:/g, '*3a')
  const startDate = new Date(currentDate.getTime() - 3600000).toISOString().replace(/\:/g, '*3a')
  const timestamp = currentDate.getTime() + 5 // add 5 seconds to guarantee the errors to appear in the query

  const linkTarget = (filter) => `https://eu-west-1.console.aws.amazon.com/cloudwatch/home?region=eu-west-1
    #logs-insights:queryDetail=
    ~(end~'${endDate}
    ~start~'${startDate}
    ~timeType~'ABSOLUTE
    ~tz~'Local
    ~editorString~'
      fields*20*40timestamp*2c*20*40message*2c*20request_uri*2c*20status*0a*7c*20
      sort*20*40timestamp*20desc*0a*7c*20
      filter*20${filter}
    ~isLiveTail~false
    ~source~(~'*2faws*2felasticbeanstalk*2f${data.AlarmDescription}*2fdocker*2fnginx));tab=logs`.replace(/\r?\n|\r|\s/g, '')

  return {
    "blocks": [
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": `*Internal Server Errors*\nEncountered request(s) with status code 500 in the last ${data.Trigger.Period} seconds.`
        }
      },
      {
        "type": "divider"
      },
      {
        "type": "context",
        "elements": [
          {
            "type": "mrkdwn",
            "text": `<${linkTarget('status*20*3d*20500*0a')}|View 500 errors>`
          },
          {
            "type": "mrkdwn",
            "text": `<${linkTarget('*40message*20like*20*2f*5c*5berror*5c*5d*2f*0a')}|View error messages>`
          }
        ]
      }
    ]
  }
}

function parseSNSMessage (message) {
  console.log('SNS Message:', message)
  return JSON.parse(message)
}

function processEvent (event, context, callback) {
  console.log('Event:', JSON.stringify(event))
  const snsMessage = parseSNSMessage(event.Records[0].Sns.Message)
  const postData = buildSlackMessage(snsMessage)
  post(webhook, postData, callback)
}

function decryptAndProcess (event, context, callback) {
  const kms = new AWS.KMS()
  const enc = { CiphertextBlob: Buffer.from(ENV.webhook, 'base64') }
  kms.decrypt(enc, (err, data) => {
    if (err) return callback(err)
    webhook = data.Plaintext.toString('ascii')
    processEvent(event, context, callback)
  })
}

exports.handler = (event, context, callback) => {
  if (webhook) {
    processEvent(event, context, callback)
  } else {
    decryptAndProcess(event, context, callback)
  }
}
