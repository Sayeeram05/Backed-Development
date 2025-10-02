from django.shortcuts import render
from django.views import View
from .models import BaseDataModel

class InvoiceUpdateView(View):
    def get(self, request):
        BaseData = BaseDataModel.objects.first()
        print(BaseData)
        if BaseData:
            print("BaseData exists")
            context = {
                'company_name': BaseData.CompanyName,
                'company_description': BaseData.Description,
                'company_pan': BaseData.PanNumber,
                'company_address': BaseData.Address,
                'company_district': BaseData.District,
                'company_state': BaseData.State,
                'company_pincode': BaseData.Pincode,
                'company_phone': BaseData.PhoneNumber,
                'company_alt_phone': BaseData.AlternateMobileNumber,
                'company_email': BaseData.Email,
                'company_tax': BaseData.TaxPercentage,
                'company_gst': BaseData.GstNumber
            }
            return render(request, 'invoiceupdatepage.html', context)
        return render(request, 'invoiceupdatepage.html')
    
    def post(self, request):
        company_name = request.POST.get('company_name')
        company_description = request.POST.get('company_description')
        company_address = request.POST.get('company_address')
        company_district = request.POST.get('company_district')
        company_state = request.POST.get('company_state')
        company_pincode = request.POST.get('company_pincode')
        company_phone = request.POST.get('company_phone')
        company_alt_phone = request.POST.get('company_alt_phone')
        company_email = request.POST.get('company_email')
        company_tax = request.POST.get('company_tax')
        company_gst = request.POST.get('company_gst')

        print("Company Name:", company_name,)
        print("Company Description:", company_description)
        print("Company Address:", company_address)
        print("Company District:", company_district)
        print("Company State:", company_state)
        print("Company Pincode:", company_pincode)
        print("Company Phone:", company_phone)
        print("Company Alternate Phone:", company_alt_phone)
        print("Company Email:", company_email)
        print("Company Tax:", company_tax)
        print("Company GST:", company_gst)

        UpdatedBaseData = BaseDataModel(
            CompanyName=company_name,
            Description=company_description,
            Address=company_address,
            District=company_district,
            State=company_state,
            Pincode=company_pincode,
            PhoneNumber=company_phone,
            AlternateMobileNumber=company_alt_phone,
            Email=company_email,
            TaxPercentage=company_tax,
            GstNumber=company_gst
        )
        UpdatedBaseData.save()

        return render(request, 'invoiceupdatepage.html')
