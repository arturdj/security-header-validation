/**
 * This file was automatically generated based on your preset configuration.
 *
 * For better type checking and IntelliSense:
 * 1. Install azion as dev dependency:
 *    npm install -D azion
 *
 * 2. Use defineConfig:
 *    import { defineConfig } from 'azion'
 *
 * 3. Replace the configuration with defineConfig:
 *    export default defineConfig({
 *      // Your configuration here
 *    })
 *
 * For more configuration options, visit:
 * https://github.com/aziontech/lib/tree/main/packages/config
 */

module.exports = {
  build: {
    preset: 'react',
    polyfills: true
  },
  storage: [
    {
      name: 'sec-head-val',
      prefix: '20250902111501',
      dir: './.edge/assets',
      edgeAccess: 'read_only'
    }
  ],
  connectors: [
    {
      name: 'sec-head-val',
      active: true,
      type: 'storage',
      attributes: {
        bucket: 'sec-head-val',
        prefix: '20250902111501'
      }
    }
  ],
  applications: [
    {
      name: 'sec-head-val',
      rules: {
        request: [
          {
            name: 'Deliver Static Assets',
            description: 'Deliver static assets directly from storage',
            active: true,
            criteria: [
              [
                {
                  variable: '${uri}',
                  conditional: 'if',
                  operator: 'matches',
                  argument:
                    '\\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|ttf|otf|woff|woff2|eot|pdf|doc|docx|xls|xlsx|ppt|pptx|mp4|webm|mp3|wav|ogg|css|js|json|xml|html|txt|csv|zip|rar|7z|tar|gz|webmanifest|map|md|yaml|yml)$'
                }
              ]
            ],
            behaviors: [
              {
                type: 'set_connector',
                attributes: {
                  value: 'sec-head-val'
                }
              },
              {
                type: 'deliver'
              }
            ]
          },
          {
            name: 'Redirect to index.html',
            description:
              'Handle all routes by rewriting to index.html for client-side routing',
            active: true,
            criteria: [
              [
                {
                  variable: '${uri}',
                  conditional: 'if',
                  operator: 'matches',
                  argument: '^\\/'
                }
              ]
            ],
            behaviors: [
              {
                type: 'set_connector',
                attributes: {
                  value: 'sec-head-val'
                }
              },
              {
                type: 'rewrite_request',
                attributes: {
                  value: '/index.html'
                }
              }
            ]
          }
        ],
        response: []
      }
    }
  ],
  workloads: [
    {
      name: 'sec-head-val',
      active: true,
      infrastructure: 1,
      protocols: {
        http: {
          versions: ['http1', 'http2'],
          httpPorts: [80],
          httpsPorts: [443],
          quicPorts: null
        }
      },
      deployments: [
        {
          name: 'sec-head-val',
          current: true,
          active: true,
          strategy: {
            type: 'default',
            attributes: {
              application: 'sec-head-val'
            }
          }
        }
      ]
    }
  ]
}
