package org.certificateservices.messages.sweeid2.dssextenstions1_1

import spock.lang.Specification
import spock.lang.Unroll

import static org.certificateservices.messages.sweeid2.dssextenstions1_1.CertType.PKC;
import static org.certificateservices.messages.sweeid2.dssextenstions1_1.CertType.QC;
import static org.certificateservices.messages.sweeid2.dssextenstions1_1.CertType.QC_SSD

class CertTypeSpec extends Specification {


	@Unroll
	def "Verify that CertType returns value #value for type #type"(){
		expect:
		type.getValue() == value
		where:
		type            | value
		PKC 			| "PKC"
		QC   			| "QC"
		QC_SSD 			| "QC/SSCD"
	}

}
