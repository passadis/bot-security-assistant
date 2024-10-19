using Microsoft.Bot.Builder;
using Microsoft.Bot.Schema;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Azure.AI.OpenAI;
using Azure;
using Azure.AI.TextAnalytics;
using OpenAI.Chat;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Text.RegularExpressions;

namespace SecurityBot.Bots
{
    public class Security : ActivityHandler
    {
        private readonly HttpClient _httpClient;
        private readonly AzureOpenAIClient _azureClient;
        private readonly string _chatDeployment;
        private readonly TextAnalyticsClient _textAnalyticsClient;
        private readonly IConfiguration _configuration;

        public Security(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _httpClient = new HttpClient();

            // Azure OpenAI Chat API configuration
            var endpoint = configuration["AzureOpenAI:Endpoint"];
            var apiKey = configuration["AzureOpenAI:ApiKey"];
            _chatDeployment = configuration["AzureOpenAI:DeploymentName"]; // Your Chat model deployment name

            // Initialize the Azure OpenAI client
            _azureClient = new AzureOpenAIClient(new Uri(endpoint), new AzureKeyCredential(apiKey));

            // Text Analytics API configuration
            var textAnalyticsEndpoint = configuration["AzureTextAnalytics:Endpoint"];
            var textAnalyticsApiKey = configuration["AzureTextAnalytics:ApiKey"];
            _textAnalyticsClient = new TextAnalyticsClient(new Uri(textAnalyticsEndpoint), new AzureKeyCredential(textAnalyticsApiKey));
        }

        protected override async Task OnMessageActivityAsync(ITurnContext<IMessageActivity> turnContext, CancellationToken cancellationToken)
        {
            var userInput = turnContext.Activity.Text.ToLower();

            // Detect if the user wants to generate a query
            if (userInput.Contains("generate"))
            {
                // If the user says "generate", extract event and date, then generate the query
                var kqlQuery = await BuildKQLQueryFromInput(userInput);
                await turnContext.SendActivityAsync(MessageFactory.Text($"Generated KQL Query: {kqlQuery}"), cancellationToken);
            }
            else if (userInput.Contains("run"))
            {
                // If the user says "run", extract event and date, then run the query
                var kqlQuery = await BuildKQLQueryFromInput(userInput);
                var queryResult = await RunKqlQueryAsync(kqlQuery);
                await turnContext.SendActivityAsync(MessageFactory.Text($"KQL Query: {kqlQuery}\n\nResult: {queryResult}"), cancellationToken);
            }
            else
            {
                // For other inputs, handle the conversation with Azure OpenAI
                await GenerateChatResponseAsync(turnContext, userInput, cancellationToken);
         
            }

        }


        // Generate responses using the Azure OpenAI Chat API without streaming
        private async Task GenerateChatResponseAsync(ITurnContext<IMessageActivity> turnContext, string userInput, CancellationToken cancellationToken)
        {
            var chatClient = _azureClient.GetChatClient(_chatDeployment);

            // Set up the chat conversation context
            var chatMessages = new List<ChatMessage>
        {
            new SystemChatMessage("You are a cybersecurity assistant responding only to Security related questions.For irrelevant topics answer with 'Irrelevant'"),
            new UserChatMessage(userInput)
        };

            // Call the Azure OpenAI API to get the complete chat response
            var chatResponse = await chatClient.CompleteChatAsync(chatMessages);

            // Access the completion content properly
            var assistantMessage = chatResponse.Value.Content.FirstOrDefault()?.Text;

            if (!string.IsNullOrEmpty(assistantMessage))
            {
                // Send the entire response to the user at once
                await turnContext.SendActivityAsync(MessageFactory.Text(assistantMessage.ToString().Trim()), cancellationToken);
            }
            else
            {
                await turnContext.SendActivityAsync(MessageFactory.Text("I'm sorry, I couldn't process your request."), cancellationToken);
            }
        }

        // Build a KQL query from the user's input using Text Analytics
        private Task<string> BuildKQLQueryFromInput(string input)
        {
            // Start with a base KQL query
            string kqlQuery = "SecurityEvent | where 1 == 1 ";

            // Use the eventMapping dictionary to map the user's input to an EventID
            var matchedEventId = eventMapping.FirstOrDefault(mapping => input.Contains(mapping.Key)).Value;

            if (matchedEventId != 0) // EventID was found
            {
                kqlQuery += $"| where EventID == {matchedEventId} ";
            }

            // Extract the DateRange (e.g., "7 days") and add it to the query
            var dateRange = ExtractDateRange(input);
            if (!string.IsNullOrEmpty(dateRange))
            {
                kqlQuery += $"| where TimeGenerated > ago({dateRange}) | project TimeGenerated, Account, Computer, EventID | take 10 ";
            }

            return Task.FromResult(kqlQuery);  // Return the constructed KQL query
        }

        private string ExtractDateRange(string input)
        {
            // Simple extraction logic to detect "7 days", "3 days", etc.
            var match = Regex.Match(input, @"(\d+)\s+days?");
            if (match.Success)
            {
                return $"{match.Groups[1].Value}d";  // Return as "7d", "3d", etc.
            }
            return null;  // Return null if no date range found
        }
        private Dictionary<string, int> eventMapping = new Dictionary<string, int>()
        {
            { "failed sign-in", 4625 },     // Failed login
            { "successful sign-in", 4624 }, // Successful login
            { "account lockout", 4740 },    // Account lockout
            { "password change", 4723 },  // Password change
            { "account creation", 4720 },   // User account created
            { "logon type", 4624 },          // Logon events
            { "registry value was modified", 4657 },          // possible brute-force, dictionary, and other password guess attacks
            { "user account was changed", 4738 },         // User account changed
            { "user account was enabled", 4722 },         // User account enabled
            { "user account was disabled", 4725 },          // User account disabled
            { "user account was deleted", 4726 },         // User account deleted
            { "user account was undeleted", 4743 },          // User account undeleted
            { "user account was locked out", 4767 },          // User account locked out
            { "user account was unlocked", 4768 },          // User account unlocked
            { "user account was created", 4720 },          // User account created
            { "attempt was made to duplicate a handle to an object", 4690 },          // An attempt was made to duplicate a handle to an object
            { "indirect access to an object was requested", 4691 },          // Indirect access to an object was requested
            { "backup of data protection master key was attempted", 4692 },          // Backup of data protection master key was attempted
            { "recovery of data protection master key was attempted", 4693 },          // Recovery of data protection master key was attempted
            { "protection of auditable protected data was attempted", 4694 },          // Protection of auditable protected data was attempted
            { "unprotection of auditable protected data was attempted", 4695 },          // Unprotection of auditable protected data was attempted
            { "a primary token was assigned to process", 4696 },          // A primary token was assigned to process
            { "a service was installed in the system", 4697 },          // A service was installed in the system
            { "a scheduled task was created", 4698 },          // A scheduled task was created
            { "a scheduled task was deleted", 4699 },          // A scheduled task was deleted
            { "a scheduled task was enabled", 4700 },          // A scheduled task was enabled
            { "a scheduled task was disabled", 4701 },          // A scheduled task was disabled
            { "a scheduled task was updated", 4702 },          // A scheduled task was updated
            { "a token right was adjusted", 4703 },          // A token right was adjusted
            { "a user right was assigned", 4704 },          // A user right was assigned
            { "a user right was removed", 4705 },          // A user right was removed
            { "a new trust was created to a domain", 4706 },          // A new trust was created to a domain
            { "a trust to a domain was removed", 4707 },          // A trust to a domain was removed
            { "IPsec Services was started", 4709 },          // IPsec Services was started
            { "IPsec Services was disabled", 4710 }          // IPsec Services was disabled
        };


        // Run KQL query in Azure Sentinel / Log Analytics
        private async Task<string> RunKqlQueryAsync(string kqlQuery)
        {
            var _workspaceId = _configuration["AzureSentinel:WorkspaceId"];
            string queryUrl = $"https://api.loganalytics.io/v1/workspaces/{_workspaceId}/query";
            var accessToken = await GetAccessTokenAsync();  // Get Azure AD token

            var requestBody = new
            {
                query = kqlQuery
            };

            var jsonContent = new StringContent(JsonConvert.SerializeObject(requestBody), Encoding.UTF8, "application/json");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");

            var response = await _httpClient.PostAsync(queryUrl, jsonContent);
            var responseBody = await response.Content.ReadAsStringAsync();

            return responseBody;  // Return the query result
        }

        // Get Azure AD token for querying Log Analytics
        private async Task<string> GetAccessTokenAsync()
        {
            var _tenantId = _configuration["AzureSentinel:TenantId"];
            var _clientId = _configuration["AzureSentinel:ClientId"];
            var _clientSecret = _configuration["AzureSentinel:ClientSecret"];
            var url = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token";
            var body = new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", _clientId },
            { "client_secret", _clientSecret },
            { "scope", "https://api.loganalytics.io/.default" }
        };

            var content = new FormUrlEncodedContent(body);
            var response = await _httpClient.PostAsync(url, content);
            var responseBody = await response.Content.ReadAsStringAsync();
            dynamic result = JsonConvert.DeserializeObject(responseBody);

            return result.access_token;
        }

        //// Recognize entities using Azure Text Analytics
        //private async Task<string> RecognizeEntitiesAsync(string input)
        //{
        //    var response = await _textAnalyticsClient.RecognizeEntitiesAsync(input);
        //    var entities = response.Value
        //        .Select(e => $"{e.Category}: {e.Text} (confidence: {e.ConfidenceScore})")
        //        .ToList();

        //    return string.Join(", ", entities);  // Return recognized entities
        //}
    }
}