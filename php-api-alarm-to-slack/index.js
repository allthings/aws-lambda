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
  const linkTarget = `https://eu-west-1.console.aws.amazon.com/cloudwatch/home?region=eu-west-1
    #logs-insights:queryDetail=
    ~(end~0
    ~start~-3600
    ~timeType~'RELATIVE
    ~unit~'seconds
    ~editorString
    ~'fields*20*40timestamp*2c*20*40message*2c*20request_uri*2c*20status*0a*7c*20sort*20*40timestamp*20desc
    ~isLiveTail~false
    ~source~(~'*2faws*2felasticbeanstalk*2f${data.Description}*2fdocker*2fnginx))`.replace(/\r?\n|\r/g, '')

  const logLink = `<${linkTarget}|View Logs>`
  return {
    channel: ENV.channel,
    username: ENV.username,
    icon_emoji: ENV.icon_emoji,
    icon_url: ENV.icon_url,
    attachments: [
      {
        fallback: data.AlarmName,
        title: "Internal Server Errors",
        text: `Encountered request(s) with status code 500 in the last ${data.Trigger.Period} seconds.\n${logLink}`,
        color: 'danger'
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
