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
        private readonly IConfiguration _configuration;
        private Dictionary<string, int> eventMapping; // Declare eventMapping here

        public Security(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _httpClient = new HttpClient();

            // Load event mappings from JSON file
            string eventMappingPath = Path.Combine(AppContext.BaseDirectory, "eventMappings.json");
            if (File.Exists(eventMappingPath))
            {
                var json = File.ReadAllText(eventMappingPath);
                eventMapping = JsonConvert.DeserializeObject<Dictionary<string, int>>(json);
            }

            // Azure OpenAI Chat API configuration
            var endpoint = configuration["AzureOpenAI:Endpoint"];
            var apiKey = configuration["AzureOpenAI:ApiKey"];
            _chatDeployment = configuration["AzureOpenAI:DeploymentName"]; // Your Chat model deployment name

            // Initialize the Azure OpenAI client
            _azureClient = new AzureOpenAIClient(new Uri(endpoint), new AzureKeyCredential(apiKey));
        }

        protected override async Task OnMessageActivityAsync(ITurnContext<IMessageActivity> turnContext, CancellationToken cancellationToken)
        {
            var userInput = turnContext.Activity.Text.ToLower();

            // Detect if the user wants to generate a query
            if (userInput.Contains("generate"))
            {
                // If the user says "generate", extract event and date, then generate the query
                var kqlQuery = await BuildKQLQueryFromInput(userInput, turnContext, cancellationToken);
                await turnContext.SendActivityAsync(MessageFactory.Text($"Generated KQL Query: {kqlQuery}"), cancellationToken);
            }
            else if (userInput.Contains("run"))
            {
                // If the user says "run", extract event and date, then run the query
                var kqlQuery = await BuildKQLQueryFromInput(userInput, turnContext, cancellationToken);
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
                new SystemChatMessage("You are a cybersecurity assistant responding only to Security related questions. For irrelevant topics answer with 'Irrelevant'"),
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
        private async Task<string> BuildKQLQueryFromInput(string input, ITurnContext<IMessageActivity> turnContext, CancellationToken cancellationToken)
        {
            // Start with a base KQL query
            string kqlQuery = "SecurityEvent | where 1 == 1 ";

            // Use the eventMapping dictionary to map the user's input to an EventID
            var matchedEventId = eventMapping.FirstOrDefault(mapping => input.Contains(mapping.Key)).Value;

            if (matchedEventId != 0) // EventID was found
            {
                kqlQuery += $"| where EventID == {matchedEventId} ";
            }
            else
            {
                // Fallback if no matching EventID is found
                await turnContext.SendActivityAsync(MessageFactory.Text("Sorry, I couldn't find a matching event ID for your request."), cancellationToken);
                return null; // Exit early if no valid EventID is found
            }

            // Extract the DateRange (e.g., "7 days") and add it to the query
            var dateRange = ExtractDateRange(input);
            if (!string.IsNullOrEmpty(dateRange))
            {
                kqlQuery += $"| where TimeGenerated > ago({dateRange}) | project TimeGenerated, Account, Computer, EventID | take 10 ";
            }

            return kqlQuery;  // Return the constructed KQL query
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
    }
}
