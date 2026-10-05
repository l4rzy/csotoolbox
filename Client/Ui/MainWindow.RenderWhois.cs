using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderWhoisReport(WhoisObject whois)
        {
            var panel = _panelWhois!;

            var txtDomain = _txtWhoisDomain!;
            var txtRegistrar = _txtWhoisRegistrar!;
            var txtDnssec = _txtWhoisDnssec!;
            var txtCreated = _txtWhoisCreated!;
            var txtExpires = _txtWhoisExpires!;
            var txtUpdated = _txtWhoisUpdated!;

            var extraPanel = _panelWhoisExtraInfo!;
            extraPanel.Children.Clear();

            var contactsPanel = _panelWhoisContacts!;
            contactsPanel.Children.Clear();

            var statusesPanel = _panelWhoisStatuses!;
            statusesPanel.Children.Clear();

            var nsPanel = _panelWhoisNameservers!;
            nsPanel.Children.Clear();
            var cardExtra = _cardWhoisExtra!;

            txtDomain.Text = whois.DomainName.ToUpper();

            var registrarInfo = whois.Registrar;
            if (!string.IsNullOrEmpty(whois.RegistrarIanaId))
                registrarInfo += $" (IANA #{whois.RegistrarIanaId})";
            txtRegistrar.Text = $"Registrar: {(string.IsNullOrEmpty(registrarInfo) ? "Unknown" : registrarInfo)}";

            txtDnssec.Text = $"DNSSEC: {(!string.IsNullOrEmpty(whois.Dnssec) ? whois.Dnssec : "Not Signed")}";
            txtDnssec.IsVisible = true;

            txtCreated.Text = $"Registered: {FormatDateTime(whois.CreatedDate, showAge: true)}";

            txtExpires.Text = $"Expires: {FormatDateTime(whois.ExpirationDate, showAge: true, isPast: false)}";

            txtUpdated.Text = $"Last Updated: {FormatDateTime(whois.UpdatedDate, showAge: true)}";

            // ── Contacts (structured sections) ──
            AddContactSection(contactsPanel, "Registrant", DraculaColors.Purple,
                whois.Registrant, whois.RegistrantName, whois.RegistrantEmail, whois.RegistrantPhone);
            AddContactSection(contactsPanel, "Admin Contact", DraculaColors.Cyan,
                whois.AdminOrg, whois.AdminName, whois.AdminEmail, whois.AdminPhone);
            AddContactSection(contactsPanel, "Tech Contact", DraculaColors.Green,
                whois.TechOrg, whois.TechName, whois.TechEmail, whois.TechPhone);

            if (contactsPanel.Children.Count == 0)
            {
                contactsPanel.Children.Add(new TextBlock
                {
                    Text = "N/A",
                    FontSize = 13,
                    Foreground = Avalonia.Media.Brush.Parse("#888888"),
                    HorizontalAlignment = HorizontalAlignment.Center
                });
            }

            AddDetailRow(extraPanel, "Registry Domain ID", whois.RegistryDomainId, showCopy: false, skipIfEmpty: true);
            AddDetailRow(extraPanel, "Registrar IANA ID", whois.RegistrarIanaId, showCopy: false, skipIfEmpty: true);
            AddDetailRow(extraPanel, "Registrar URL", whois.RegistrarUrl, showCopy: true, skipIfEmpty: true);
            AddDetailRow(extraPanel, "Abuse Email", whois.AbuseEmail, showCopy: true, skipIfEmpty: true);
            AddDetailRow(extraPanel, "Abuse Phone", whois.AbusePhone, showCopy: true, skipIfEmpty: true);
            cardExtra.IsVisible = extraPanel.Children.Count > 0;

            // Statuses
            if (whois.Statuses != null && whois.Statuses.Count > 0)
            {
                foreach (var status in whois.Statuses)
                    statusesPanel.Children.Add(CreateBadgeBorder(status, DraculaColors.Red));
            }
            else
            {
                statusesPanel.Children.Add(new TextBlock { Text = "No status info", Foreground = Avalonia.Media.Brushes.Gray, FontSize = 12 });
            }

            // Nameservers
            if (whois.Nameservers != null && whois.Nameservers.Count > 0)
            {
                foreach (var ns in whois.Nameservers)
                    nsPanel.Children.Add(CreateBadgeBorder(ns, DraculaColors.Green));
            }
            else
            {
                nsPanel.Children.Add(new TextBlock { Text = "No nameservers", Foreground = Avalonia.Media.Brushes.Gray, FontSize = 12 });
            }

            panel.IsVisible = true;
        }



        private void AddContactSection(StackPanel container, string title, string dotColor,
            string org, string name, string email, string phone)
        {
            var section = new StackPanel { Spacing = 6 };

            var headerRow = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 8 };
            headerRow.Children.Add(new TextBlock
            {
                Text = "●",
                Foreground = Avalonia.Media.Brush.Parse(dotColor),
                FontSize = 14,
                VerticalAlignment = VerticalAlignment.Center
            });
            headerRow.Children.Add(new TextBlock
            {
                Text = title,
                FontSize = 14,
                FontWeight = Avalonia.Media.FontWeight.SemiBold,
                Foreground = Avalonia.Media.Brush.Parse(dotColor),
                VerticalAlignment = VerticalAlignment.Center
            });
            section.Children.Add(headerRow);

            void AddField(string label, string value, bool showCopy = false)
            {
                AddDetailRow(
                    panel: section,
                    label: label,
                    value: value,
                    labelWidth: "140",
                    fontSize: 13,
                    showCopy: showCopy,
                    margin: new Thickness(16, 0, 0, 0),
                    foregroundColorHex: "#CCCCCC",
                    maxLines: null,
                    skipIfEmpty: true
                );
            }

            AddField("Name/Org", org);
            AddField("Name", name);
            AddField("Email", email, showCopy: true);
            AddField("Phone", phone, showCopy: true);

            if (section.Children.Count > 1)
                container.Children.Add(section);
        }

    }
}
