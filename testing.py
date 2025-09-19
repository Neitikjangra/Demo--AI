import whois


w = whois.whois("https://www.sih.gov.in/")
creation = w.creation_date
print(creation)