using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Layout;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderRdapReport(RdapResult rdap)
        {

            if (rdap.LdhName != null)
                RenderRdapDomain(rdap);
            else
                RenderRdapIp(rdap);

            _panelRdap!.IsVisible = true;
        }

        private void RenderRdapDomain(RdapResult rdap)
        {
            _cardRdapContacts!.IsVisible = false;
            _gridRdapDomainDetails!.IsVisible = false;

            // Header — domain name, registrar, abuse contact, DNSSEC
            _txtRdapName!.Text = (rdap.UnicodeName ?? rdap.LdhName!).ToUpper();

            var registrar = rdap.Entities.FirstOrDefault(e => e.Roles.Contains("registrar"));
            var registrarInfo = registrar?.Fn ?? "";
            if (!string.IsNullOrEmpty(registrar?.Handle))
                registrarInfo += $" (IANA #{registrar.Handle})";
            _txtRdapRegistrar.Text = $"Registrar: {(string.IsNullOrEmpty(registrarInfo) ? "N/A" : registrarInfo)}";

            var abuse = rdap.Entities.FirstOrDefault(e => e.Roles.Contains("abuse"));
            var abuseParts = new List<string>();
            if (abuse != null)
            {
                if (!string.IsNullOrEmpty(abuse.Email)) abuseParts.Add($"Email: {abuse.Email}");
                if (!string.IsNullOrEmpty(abuse.Tel)) abuseParts.Add($"Phone: {abuse.Tel}");
            }
            _txtRdapAbuseContact.Text = $"Abuse Contact: {(abuseParts.Count > 0 ? string.Join(" | ", abuseParts) : "N/A")}";

            var extras = new List<string>();
            if (rdap.SecureDns.HasValue)
                extras.Add(rdap.SecureDns.Value ? "DNSSEC: Signed" : "DNSSEC: Not Signed");
            _txtRdapSecureDns!.IsVisible = extras.Count > 0;
            if (extras.Count > 0)
            {
                _txtRdapSecureDns.Text = string.Join(" | ", extras);
            }

            // Events
            var eventsPanel = _panelRdapEvents!;
            eventsPanel.Children.Clear();
            foreach (var ev in rdap.Events)
            {
                if (string.IsNullOrEmpty(ev.Date)) continue;
                eventsPanel.Children.Add(new TextBlock
                {
                    Inlines = new InlineCollection
                    {
                        new Run { Text = $"{FormatEventAction(ev.Action)}: ", FontWeight = Avalonia.Media.FontWeight.Bold, Foreground = Avalonia.Media.Brush.Parse("#CCCCCC") },
                        new Run { Text = FormatDateTime(ev.Date, showAge: true, isPast: ev.Action != "expiration"), Foreground = Avalonia.Media.Brush.Parse("#CCCCCC") }
                    },
                    FontSize = 14,
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap
                });
            }

            // Contacts — registrant, admin, tech
            var contactsPanel = _panelRdapContacts!;
            contactsPanel.Children.Clear();
            AddContactSectionIfExists(contactsPanel, "Registrant", DraculaColors.Purple, "registrant", rdap);
            AddContactSectionIfExists(contactsPanel, "Admin Contact", DraculaColors.Cyan, "administrative", rdap);
            AddContactSectionIfExists(contactsPanel, "Tech Contact", DraculaColors.Green, "technical", rdap);
            if (contactsPanel.Children.Count > 0)
                _cardRdapContacts.IsVisible = true;

            // Statuses + Nameservers grid
            _gridRdapDomainDetails!.IsVisible = true;
            var statusesPanel = _panelRdapStatuses!;
            statusesPanel.Children.Clear();
            foreach (var status in rdap.Statuses)
                statusesPanel.Children.Add(CreateBadgeBorder(status, DraculaColors.Red));

            var nsPanel = _panelRdapNameservers!;
            nsPanel.Children.Clear();
            if (rdap.Nameservers is { Count: > 0 })
            {
                foreach (var ns in rdap.Nameservers)
                    nsPanel.Children.Add(CreateBadgeBorder(ns.LdhName, DraculaColors.Green));
            }
            else
            {
                nsPanel.Children.Add(new TextBlock
                {
                    Text = "N/A",
                    Foreground = Avalonia.Media.Brushes.Gray,
                    FontSize = 12
                });
            }
        }

        private void RenderRdapIp(RdapResult rdap)
        {
            _cardRdapContacts!.IsVisible = false;
            _gridRdapDomainDetails!.IsVisible = false;

            // Header — CIDR as big text, then name/type/country/WHOIS
            _txtRdapName!.Text = rdap.Cidrs is { Count: > 0 }
                ? string.Join(", ", rdap.Cidrs)
                : $"{rdap.StartAddress} - {rdap.EndAddress}";

            _txtRdapRegistrar.Text = $"Name: {rdap.Name ?? "N/A"}";
            _txtRdapAbuseContact!.Text = null;
            _txtRdapAbuseContact.Inlines?.Clear();
            FormatHelpers.SetCountryTextWithFlag(_txtRdapAbuseContact, rdap.Country, null);
            if (!string.IsNullOrEmpty(rdap.Port43))
            {
                _txtRdapAbuseContact.Inlines!.Add(new Run { Text = " | ", Foreground = Avalonia.Media.Brush.Parse("#aaaaaa") });
                _txtRdapAbuseContact.Inlines!.Add(new Run { Text = rdap.Port43, Foreground = Avalonia.Media.Brush.Parse("#aaaaaa") });
            }
            _txtRdapSecureDns!.IsVisible = false;

            // Events
            var eventsPanel = _panelRdapEvents!;
            eventsPanel.Children.Clear();
            foreach (var ev in rdap.Events)
            {
                if (string.IsNullOrEmpty(ev.Date)) continue;
                eventsPanel.Children.Add(new TextBlock
                {
                    Text = $"{FormatEventAction(ev.Action)}: {FormatDateTime(ev.Date, showAge: true, isPast: ev.Action != "expiration")}",
                    FontSize = 14,
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                    Foreground = Avalonia.Media.Brush.Parse("#CCCCCC")
                });
            }

            // Contacts — registrant, admin, tech, abuse
            var contactsPanel = _panelRdapContacts!;
            contactsPanel.Children.Clear();
            AddContactSectionIfExists(contactsPanel, "Registrant", DraculaColors.Purple, "registrant", rdap);
            AddContactSectionIfExists(contactsPanel, "Admin Contact", DraculaColors.Cyan, "administrative", rdap);
            AddContactSectionIfExists(contactsPanel, "Tech Contact", DraculaColors.Green, "technical", rdap);
            AddContactSectionIfExists(contactsPanel, "Abuse Contact", DraculaColors.Red, "abuse", rdap);
            if (contactsPanel.Children.Count > 0)
                _cardRdapContacts.IsVisible = true;
        }

        private void AddContactSectionIfExists(StackPanel container, string title, string color, string role, RdapResult rdap)
        {
            var entity = rdap.Entities.FirstOrDefault(e => e.Roles.Contains(role));
            if (entity == null || (string.IsNullOrEmpty(entity.Fn) && string.IsNullOrEmpty(entity.Email) && string.IsNullOrEmpty(entity.Tel)))
                return;
            AddContactSection(container, title, color, entity.Fn, "", entity.Email, entity.Tel);
        }

        private static string FormatEventAction(string action) => action switch
        {
            "registration" => "Registered",
            "expiration" => "Expires",
            "last changed" => "Last Changed",
            "last update of RDAP database" => "Database Updated",
            _ => char.ToUpper(action[0]) + action[1..]
        };
    }
}
